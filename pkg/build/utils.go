package build

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"go.uber.org/zap"
	"gopkg.in/yaml.v2"
	helmpack "helm.sh/helm/v3/pkg/action"
	chartLoader "helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/chartutil"
)

type DockerOutputLine struct {
	Stream string `json:"stream"`
}

type ErrorLine struct {
	Error       string      `json:"error"`
	ErrorDetail ErrorDetail `json:"errorDetail"`
}

type ErrorDetail struct {
	Message string `json:"message"`
}

type BuildConfigMap map[string]*BuildConfig

func AwsSession(region, key, secret string) (*session.Session, error) {
	Logger.Info("creating aws session", zap.String("region", region), zap.String("key", key), zap.String("secret", secret))
	awsConfig := &aws.Config{}
	if region != "" {
		awsConfig.Region = aws.String(region)
	}

	if key != "" && secret != "" {
		awsConfig.Credentials = credentials.NewStaticCredentials(key, secret, "")
	}

	sess, err := session.NewSession(awsConfig)
	if err != nil {
		fmt.Println(err.Error())
		return nil, errors.New("unable to create aws sessions " + err.Error())
	}

	return sess, nil
}

func LoadConfig(session *session.Session, tableName string, keys []string) (map[string]*BuildConfig, error) {
	Logger.Info("loading configs from dynamodb", zap.String("tableName", tableName), zap.Strings("keys", keys))
	if len(keys) < 1 {
		return nil, fmt.Errorf("expecting at least one key to filter the configs")
	}

	attrs := []expression.OperandBuilder{}
	for _, el := range keys {
		// attrs = append(attrs, &dynamodb.AttributeValue{
		// 	S: aws.String(el),
		// })
		attrs = append(attrs, expression.Value(el))
	}

	// list := (&dynamodb.AttributeValue{}).SetL(attrs)

	filt := expression.Name("id").In(attrs[0], attrs[1:]...)
	// proj := expression.NamesList(expression.Name("SongTitle"), expression.Name("AlbumTitle"))
	expr, err := expression.NewBuilder().WithFilter(filt).Build()
	if err != nil {
		return nil, fmt.Errorf("failed to create the Expression, %v", err)
	}

	input := &dynamodb.ScanInput{
		TableName:                 aws.String(tableName),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		FilterExpression:          expr.Filter(),
		ProjectionExpression:      expr.Projection(),
	}

	configs := make(map[string]*BuildConfig)
	db := dynamodb.New(session)
	err = db.ScanPages(input, func(page *dynamodb.ScanOutput, last bool) bool {
		recs := []*BuildConfig{}

		err := dynamodbattribute.UnmarshalListOfMaps(page.Items, &recs)
		if err != nil {
			panic(fmt.Sprintf("failed to unmarshal Dynamodb Scan Items, %v", err))
		}
		for _, element := range recs {
			configs[element.ID] = element
		}

		return true // keep paging
	})
	if err != nil {
		return nil, err
	}

	// j, err := json.MarshalIndent(configs, "", "  ")
	// if err != nil {
	// 	return nil, err
	// }
	Logger.Info("response from dynamo db query", zap.String("tableName", tableName), zap.Strings("keys", keys), zap.Any("response", configs))
	return configs, err
}

func GetRepository(session *session.Session, registry, repoName string) (*ecr.Repository, error) {
	Logger.Info("fetching ecr repository details", zap.String("reponame", repoName))
	r := ecr.New(session)
	input := &ecr.DescribeRepositoriesInput{
		RepositoryNames: []*string{
			aws.String(repoName),
		},
	}
	if registry != "" {
		input.RegistryId = aws.String(registry)
	}
	resp, err := r.DescribeRepositories(input)

	if len(resp.Repositories) != 1 {
		return nil, fmt.Errorf("expecting 1 item in the ecr describe repo result, got %d", len(resp.Repositories))
	}

	return resp.Repositories[0], err
}

func PrepareEcr(session *session.Session, registry, repoName string) (*ecr.Repository, error) {
	Logger.Info("setting up the ecr repository")
	r := ecr.New(session)
	input := &ecr.CreateRepositoryInput{
		RepositoryName: aws.String(repoName),
	}
	if registry != "" {
		input.RegistryId = aws.String(registry)
	}
	resp, err := r.CreateRepository(input)
	if err != nil {
		if err.(awserr.Error).Code() != ecr.ErrCodeRepositoryAlreadyExistsException {
			return nil, err
		} else {
			return GetRepository(session, registry, repoName)
		}
	}
	return resp.Repository, nil
}

func GetECRAuthData(session *session.Session) (*ecr.AuthorizationData, error) {
	Logger.Info("preparing ecr auth data for docker login")
	r := ecr.New(session)
	aout, err := r.GetAuthorizationToken(&ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return nil, err
	}

	if len(aout.AuthorizationData) < 1 {
		return nil, fmt.Errorf("could not ecr login auth data")
	}

	return aout.AuthorizationData[0], nil
}

func PushImageToECR(session *session.Session, repoName, tag string) error {
	Logger.Info("pushing image to the ecr repo using ecr cli", zap.String("repoName", repoName))
	r := ecr.New(session)
	_, err := r.PutImage(&ecr.PutImageInput{

		RepositoryName: aws.String(repoName),
		ImageTag:       aws.String(tag),
		ImageManifest:  aws.String("{\n   \"schemaVersion\": 2,\n   \"mediaType\": \"application/vnd.docker.distribution.manifest.list.v2+json\",\n   \"manifests\": [\n      {\n         \"mediaType\": \"application/vnd.docker.distribution.manifest.v2+json\",\n         \"size\": 527,\n         \"digest\": \"sha256:dca71257cd2e72840a21f0323234bb2e33fea6d949fa0f21c5102146f583486b\",\n         \"platform\": {\n            \"architecture\": \"amd64\",\n            \"os\": \"linux\"\n         }\n      },\n      {\n         \"mediaType\": \"application/vnd.docker.distribution.manifest.v2+json\",\n         \"size\": 527,\n         \"digest\": \"sha256:9cd47e9327430990c932b19596f8760e7d1a0be0311bb31bab3170bec5f27358\",\n         \"platform\": {\n            \"architecture\": \"arm\",\n            \"os\": \"linux\",\n            \"variant\": \"v5\"\n         }\n      },\n      {\n         \"mediaType\": \"application/vnd.docker.distribution.manifest.v2+json\",\n         \"size\": 527,\n         \"digest\": \"sha256:842295d11871c16bbce4d30cabc9b0f1e0cc40e49975f538179529d7798f77d8\",\n         \"platform\": {\n            \"architecture\": \"arm\",\n            \"os\": \"linux\",\n            \"variant\": \"v6\"\n         }\n      },\n      {\n         \"mediaType\": \"application/vnd.docker.distribution.manifest.v2+json\",\n         \"size\": 527,\n         \"digest\": \"sha256:0dd359f0ea0f644cbc1aa467681654c6b4332015ae37af2916b0dfb73b83fd52\",\n         \"platform\": {\n            \"architecture\": \"arm\",\n            \"os\": \"linux\",\n            \"variant\": \"v7\"\n         }\n      },\n      {\n         \"mediaType\": \"application/vnd.docker.distribution.manifest.v2+json\",\n         \"size\": 527,\n         \"digest\": \"sha256:121373e88baca4c1ef533014de2759e002961de035607dd35d00886b052e37cf\",\n         \"platform\": {\n            \"architecture\": \"arm64\",\n            \"os\": \"linux\",\n            \"variant\": \"v8\"\n         }\n      },\n      {\n         \"mediaType\": \"application/vnd.docker.distribution.manifest.v2+json\",\n         \"size\": 527,\n         \"digest\": \"sha256:ccff0c7e8498c0bd8d4705e663084c25810fd064a184671a050e1a43b86fb091\",\n         \"platform\": {\n            \"architecture\": \"386\",\n            \"os\": \"linux\"\n         }\n      },\n      {\n         \"mediaType\": \"application/vnd.docker.distribution.manifest.v2+json\",\n         \"size\": 527,\n         \"digest\": \"sha256:0dc4e9a14237cae2d8e96e9e310116091c5ed4934448d7cfd22b122778964f11\",\n         \"platform\": {\n            \"architecture\": \"mips64le\",\n            \"os\": \"linux\"\n         }\n      },\n      {\n         \"mediaType\": \"application/vnd.docker.distribution.manifest.v2+json\",\n         \"size\": 528,\n         \"digest\": \"sha256:04ebe37e000dcd9b1386af0e2d9aad726cbd1581f82067bea5cd2532b1f06310\",\n         \"platform\": {\n            \"architecture\": \"ppc64le\",\n            \"os\": \"linux\"\n         }\n      },\n      {\n         \"mediaType\": \"application/vnd.docker.distribution.manifest.v2+json\",\n         \"size\": 528,\n         \"digest\": \"sha256:c10e75f6e5442f446b7c053ff2f360a4052f759c59be9a4c7d144f60207c6eda\",\n         \"platform\": {\n            \"architecture\": \"s390x\",\n            \"os\": \"linux\"\n         }\n      }\n   ]\n}\n"),
	})

	if err != nil {
		return err
	}
	return nil
}

// func DoVersion(prevVersion, commitType string, sha string, build, extra string) string {
// 	Logger.Info("preparing version information related to the build")
// 	shortsha := sha[0:7]
// 	version := shortsha
// 	switch commitType {
// 	case "tag":
// 		//extra should be the tag
// 		version = extra
// 	// case "pr":
// 	// 	version = fmt.Sprintf("%s-%s.pr-%s.%s", prevVersion, shortsha, extra, build)
// 	default:
// 		version = fmt.Sprintf("%s-%s.%s", prevVersion, extra, build)
// 	}

// 	return version
// }

func compress(src string, buf io.Writer) error {
	Logger.Info("archiving the source dir for docker build", zap.String("src", src))
	// tar > gzip > buf
	// zr := gzip.NewWriter(buf)
	tw := tar.NewWriter(buf)

	// walk through every file in the folder
	filepath.Walk(src, func(file string, fi os.FileInfo, err error) error {
		// generate tar header
		header, err := tar.FileInfoHeader(fi, file)
		if err != nil {
			return err
		}

		// must provide real name
		// (see https://golang.org/src/archive/tar/common.go?#L626)
		header.Name = filepath.ToSlash(file)

		// write header
		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		// if not a dir, write file content
		if !fi.IsDir() {
			data, err := os.Open(file)
			if err != nil {
				return err
			}
			if _, err := io.Copy(tw, data); err != nil {
				return err
			}
		}
		return nil
	})

	// produce tar
	if err := tw.Close(); err != nil {
		return err
	}
	// produce gzip
	// if err := zr.Close(); err != nil {
	// 	return err
	// }
	//
	return nil
}

func PushImage(client *client.Client, auth string, image string) error {
	Logger.Info("pushing image to ecr repo using docker cli", zap.String("image", image))
	ctx := context.Background()

	resp, err := client.ImagePush(ctx, image, types.ImagePushOptions{
		// PrivilegeFunc: func() (string, error) {
		// 	return "X-Registry-Auth:" + auth, nil
		// },
		RegistryAuth: auth,
	})

	if err != nil {
		return err
	}
	defer resp.Close()

	print(resp)
	return nil
}

func BuildImage(client *client.Client, tags []string, build, dockerFilepath string) error {
	Logger.Info("build docker image with docker cli", zap.String("dockerFilepath", dockerFilepath))
	ctx := context.Background()

	// var buf bytes.Buffer
	buf := new(bytes.Buffer)
	err := compress(build, buf)
	if err != nil {
		return err
	}

	// Create a buffer
	tw := tar.NewWriter(buf)
	defer tw.Close()

	// Create a filereader
	dockerFileReader, err := os.Open(dockerFilepath)
	if err != nil {
		return err
	}

	// Read the actual Dockerfile
	readDockerFile, err := ioutil.ReadAll(dockerFileReader)
	if err != nil {
		return err
	}

	// Make a TAR header for the file
	tarHeader := &tar.Header{
		Name: dockerFilepath,
		Size: int64(len(readDockerFile)),
	}

	// Writes the header described for the TAR file
	err = tw.WriteHeader(tarHeader)
	if err != nil {
		return err
	}

	// Writes the dockerfile data to the TAR file
	_, err = tw.Write(readDockerFile)
	if err != nil {
		return err
	}

	dockerFileTarReader := bytes.NewReader(buf.Bytes())

	// Define the build options to use for the file
	// https://godoc.org/github.com/docker/docker/api/types#ImageBuildOptions
	buildOptions := types.ImageBuildOptions{
		Context:    dockerFileTarReader,
		Dockerfile: dockerFilepath,
		Remove:     true,
		Tags:       tags,
		PullParent: true,
	}

	// Build the actual image
	imageBuildResponse, err := client.ImageBuild(
		ctx,
		dockerFileTarReader,
		buildOptions,
	)

	if err != nil {
		return err
	}

	// Read the STDOUT from the build process
	defer imageBuildResponse.Body.Close()
	err = print(imageBuildResponse.Body)
	if err != nil {
		return err
	}
	// _, err = io.Copy(os.Stdout, imageBuildResponse.Body)
	// if err != nil {
	// 	return err
	// }

	return nil
}

func print(rd io.Reader) error {
	var lastLine string
	fmt.Print("\nDocker build logs\n")
	scanner := bufio.NewScanner(rd)
	line := &DockerOutputLine{}
	prevLine := ""
	for scanner.Scan() {
		lastLine = scanner.Text()
		json.Unmarshal([]byte(lastLine), line)
		if prevLine != line.Stream {
			fmt.Print(line.Stream)
		}
		prevLine = line.Stream
	}

	errLine := &ErrorLine{}
	json.Unmarshal([]byte(lastLine), errLine)
	if errLine.Error != "" {
		fmt.Println("ERROR: " + errLine.Error)
		fmt.Print("\nDocker build logs ends here\n\n")
		return errors.New(errLine.Error)
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}

func CreateDockerClient() (*client.Client, error) {
	Logger.Info("creating docker client")
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	return cli, err
}

func Unzip(src, dest string) (string, error) {
	Logger.Info("unziping archive", zap.String("src", src), zap.String("dest", dest))
	r, err := zip.OpenReader(src)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := r.Close(); err != nil {
			panic(err)
		}
	}()

	os.MkdirAll(dest, 0755)

	// Closure to address file descriptors issue with all the deferred .Close() methods
	extractAndWriteFile := func(f *zip.File) error {
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer func() {
			if err := rc.Close(); err != nil {
				panic(err)
			}
		}()

		path := filepath.Join(dest, f.Name)

		// Check for ZipSlip (Directory traversal)
		if !strings.HasPrefix(path, filepath.Clean(dest)+string(os.PathSeparator)) {
			return fmt.Errorf("illegal file path: %s", path)
		}

		if f.FileInfo().IsDir() {
			os.MkdirAll(path, f.Mode())
		} else {
			os.MkdirAll(filepath.Dir(path), f.Mode())
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
			if err != nil {
				return err
			}
			defer func() {
				if err := f.Close(); err != nil {
					panic(err)
				}
			}()

			_, err = io.Copy(f, rc)
			if err != nil {
				return err
			}
		}
		return nil
	}
	root := "/"
	for i, f := range r.File {
		if i == 0 {
			root = f.Name
		}
		// fmt.Println(f.Name)
		err := extractAndWriteFile(f)
		if err != nil {
			return "", err
		}
	}

	return root, nil
}

func DownloadFile(url string, outfile string) (string, error) {
	Logger.Info("downloading file", zap.String("url", url), zap.String("out", outfile))
	// outfile := "chart_scaffold.zip"
	out, err := os.Create(outfile)
	if err != nil {
		return "", err
	}
	defer out.Close()

	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	n, err := io.Copy(out, resp.Body)
	if err != nil {
		return "", err
	}

	fmt.Printf("downloaded file from %s  and saved to %s, total bytes writter %d\n", url, outfile, n)
	return outfile, nil
}

func HelmPackage(chartdir, outdir string) (string, error) {
	Logger.Info("helm package", zap.String("chartdir", chartdir), zap.String("outdir", outdir))
	chart, err := chartLoader.LoadDir(chartdir)
	if err != nil {
		return "", err
	}
	path, err := chartutil.Save(chart, outdir)
	if err != nil {
		return "", err
	}

	return path, nil
}

func IsDir(path string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		log.Println("is dir file open error " + err.Error())
		return false, err
	}
	defer file.Close()

	// This returns an *os.FileInfo type
	fileInfo, err := file.Stat()
	if err != nil {
		log.Println("fileinfo error " + err.Error())
		return false, err
	}

	// skip directories
	if fileInfo.IsDir() {
		return true, nil
	}
	return false, nil
}

func ParseTemplates(dir string, attributes map[string]string) error {
	Logger.Info("parsing templates", zap.String("src", dir), zap.Any("attr", attributes))
	err := filepath.Walk(dir, func(path string, info os.FileInfo, exerr error) error {
		isdir, err := IsDir(path)
		if isdir {
			fmt.Println(path + " is directory")
			return err
		}

		fname := filepath.Base(path)
		templ := template.New(fname).Delims("+(", ")")

		// fmt.Println("at here path is " + path)

		t, err := templ.ParseFiles(path)
		if err != nil {
			Logger.Info("parse error ", zap.Error(err))
			return err
		}
		f, err := os.Create(path)
		if err != nil {
			Logger.Info("create file error ", zap.Error(err))
			return err
		}

		err = t.Execute(f, attributes)
		if err != nil {
			Logger.Info("execute template error", zap.Error(err))
			return err
		}
		f.Close()

		return err
	})

	return err
}

func MergeValues(chartdir, valuesPath string) error {
	Logger.Info("merging values to chart", zap.String("chart", chartdir), zap.Any("valuesPath", valuesPath))
	chart, err := chartLoader.LoadDir(chartdir)
	if err != nil {
		return err
	}
	if valuesPath != "" {
		v, err := chartutil.ReadValuesFile(valuesPath)
		if err != nil {
			return err
		}
		val := mergeMaps(chart.Values, v)

		// chart.Values = val

		d, err := yaml.Marshal(val)
		if err != nil {
			Logger.Error("error while yaml marshal", zap.Error(err))
			return err
		}

		err = os.WriteFile(chartdir+"/values.yaml", d, 0755)
		if err != nil {
			Logger.Error("error while writing to values.yaml", zap.Error(err))
			return err
		}
		// fmt.Println(string(d))

		// chart.Values = finalV
	}

	return nil
}

func Package(chartdir, outdir, appversion, chartversion string) (string, error) {
	Logger.Info("doing helm packaging", zap.String("chart", chartdir), zap.String("out", outdir), zap.String("version", appversion))
	pkg := helmpack.NewPackage()
	pkg.AppVersion = appversion
	pkg.Version = chartversion
	pkg.Destination = outdir
	out, err := pkg.Run(chartdir, nil)
	return out, err
}

func HelmPush(repo, user, pass, path string) error {
	Logger.Info("helm push to chart repo", zap.String("repo", repo), zap.String("path", path))
	b := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", user, pass)))
	auth := "Basic " + b
	url := repo + "/api/charts"
	err := SendPostRequest(url, path, "chart", auth)
	return err
}

func SendPostRequest(url string, filename string, filetype string, auth string) error {
	file, err := os.Open(filename)
	if err != nil {
		Logger.Error("unable to open file", zap.String("file", filename))
		return err
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile(filetype, filepath.Base(file.Name()))
	if err != nil {
		Logger.Error("unable to create formm file", zap.String("file", filename))
		return err
	}

	io.Copy(part, file)
	writer.Close()
	request, err := http.NewRequest("POST", url, body)
	if err != nil {
		Logger.Error("unable to create http request", zap.String("url", url))
		return err
	}

	request.Header.Add("Content-Type", writer.FormDataContentType())
	if auth != "" {
		request.Header.Add("Authorization", auth)
	}
	client := &http.Client{}

	response, err := client.Do(request)
	if err != nil {
		Logger.Error("unable to make http request", zap.String("url", url))
		return err
	}
	defer response.Body.Close()

	respo, err := ioutil.ReadAll(response.Body)
	if err != nil {
		Logger.Error("error while reading http response", zap.String("url", url))
		return err
	}

	if response.StatusCode < 200 || response.StatusCode > 399 {
		Logger.Info("failed to uplaod to repo", zap.ByteString("response", respo), zap.String("httpstatus", response.Status))
		return fmt.Errorf("error while uploading to repo, status %s", response.Status)
	}

	Logger.Info("succesfully uploaded chart to repo", zap.ByteString("response", respo), zap.String("httpstatus", response.Status))

	return nil
}

func mergeMaps(a, b map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(a))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		// If you use map[string]interface{}, ok is always false here.
		// Because yaml.Unmarshal will give you map[interface{}]interface{}.
		if v, ok := v.(map[string]interface{}); ok {
			if bv, ok := out[k]; ok {
				if bv, ok := bv.(map[string]interface{}); ok {
					out[k] = mergeMaps(bv, v)
					continue
				}
			}
		}
		out[k] = v
	}
	return out
}
