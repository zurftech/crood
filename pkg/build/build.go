package build

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/docker/docker/api/types"
	"go.uber.org/zap"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
)

var finalOutputString string = `


	=================================== Build Success ==================================

	App name: %s

	Version: %s

	Docker Url: %s

	Helm Repo: %s

	=====================================================================================
	
	`

var buildNotes string = `AppName=%s
Version=%s
DockerRepoUrl=%s
DockerImageUrl=%s
HelmRrepoUrl=%s
HelmChartName=%s
HelmChartVersion=%s`

func BuildNotes(AppName, Version, DockerRepoUrl, DockerImageUrl, HelmRrepoUrl, HelmChartName, HelmChartVersion string) string {
	return fmt.Sprintf(buildNotes, AppName, Version, DockerRepoUrl, DockerImageUrl, HelmRrepoUrl, HelmChartName, HelmChartVersion)
}

func WriteBuildNotes(filename, notes string) error {
	return os.WriteFile(filename, []byte(notes), 0755)
}

const (
	BuildConfigTable = "buildConfigs"
)

var Logger *zap.Logger

func Build(config *BuildConfig) {
	if Logger == nil {
		Logger, _ = zap.NewProduction()
		defer Logger.Sync() // flushes buffer, if any
	}

	defaultConfig := config
	err := defaultConfig.Prepare()
	if err != nil {
		Logger.Error(err.Error())
		panic(err)
	}

	Logger.Info("build config", zap.Any("config", config))
	Logger.Info("starting the build process")

	version := defaultConfig.Version
	appname := defaultConfig.AppName

	ecrSess, err := AwsSession(*defaultConfig.FgECRRegion, *defaultConfig.FgECRAccessKey, *defaultConfig.FgECRSecret)
	if err != nil {
		Logger.Error(err.Error())
		panic(err)
	}

	repo, err := PrepareEcr(ecrSess, *defaultConfig.FgECRRegistryID, appname)
	if err != nil {
		Logger.Error(err.Error())
		panic(err)
	}

	repoUrl := *repo.RepositoryUri
	dockertag := repoUrl + ":" + version

	chartZipPath := "/tmp/chart_skaffold.zip"
	chartZipExtractTo := "/tmp/chart_skaffold/"

	err = os.RemoveAll(chartZipExtractTo)
	if err != nil {
		Logger.Error("unable to delete directory", zap.Error(err))
		panic(err)
	}

	Logger.Info("repository url", zap.String("url", dockertag))

	// mydir, err := os.Getwd()
	// if err != nil {
	// 	fmt.Println(err)
	// }
	// fmt.Println(mydir)
	// fmt.Println(buildConfig)
	// os.Exit(0)

	dockerCli, err := CreateDockerClient()
	if err != nil {
		Logger.Error(err.Error())
		panic(err)
	}

	err = BuildImage(dockerCli, []string{dockertag}, ".", "Dockerfile", defaultConfig.InfraUserKey)
	if err != nil {
		Logger.Error(err.Error())
		panic(err)
	}
	// dockertag = "952679535946.dkr.ecr.ap-southeast-1.amazonaws.com/testappname:1.0.4-1644065604"

	auth, err := GetECRAuthData(ecrSess)
	if err != nil {
		Logger.Error(err.Error())
		panic(err)
	}
	finished := make(chan error)
	go worker(finished, strings.Trim(*defaultConfig.HelmBasePath, " "), chartZipPath)

	parsedToken, e := base64.StdEncoding.DecodeString(*auth.AuthorizationToken)
	if e != nil {
		Logger.Error(err.Error())
		panic(e)
	}
	parts := strings.Split(string(parsedToken), ":")
	authConfig := types.AuthConfig{
		Username: parts[0],
		Password: parts[1],
	}
	encodedJSON, err := json.Marshal(authConfig)
	if err != nil {
		panic(err)
	}
	authStr := base64.URLEncoding.EncodeToString(encodedJSON)

	err = PushImage(dockerCli, authStr, dockertag)
	if err != nil {
		Logger.Error(err.Error())
		panic(err)
	}

	err = <-finished
	close(finished)
	if err != nil {
		Logger.Error("error downloading file" + err.Error())
		panic(err)
	}

	root, err := Unzip(chartZipPath, chartZipExtractTo)
	if err != nil {
		Logger.Error(err.Error())
		panic(err)
	}

	// root := "chart-scaffold-main/"

	chartSkaffoldDir := chartZipExtractTo + root
	// chartDir := strings.TrimSuffix(chartSkaffoldDir, string(os.PathSeparator)) + "-out" + string(os.PathSeparator)

	// fmt.Println(chartSkaffoldDir)

	if defaultConfig.HelmValueOverride != "" {
		overrideValues := defaultConfig.HelmValueOverride
		myfile, e := os.Stat(overrideValues)
		if e != nil {
			if os.IsNotExist(e) {
				Logger.Warn("the override files are not present, ignoring and continuing")
			}
			Logger.Error("error while opening the value override file", zap.Error(e))
			panic(e)
		} else if myfile.IsDir() {
			Logger.Warn("the override files given are directory, ignoring and continuing")
		} else {
			err = MergeValues(chartSkaffoldDir, overrideValues)
			if err != nil {
				Logger.Error("unable to merge values from source override", zap.Error(err))
				panic(err)
			}
		}
	}

	injectAttributes := make(map[string]string)
	injectAttributes["AppName"] = appname
	injectAttributes["ImageRepository"] = repoUrl

	err = ParseTemplates(chartSkaffoldDir, injectAttributes)
	if err != nil {
		Logger.Error(err.Error())
		panic(err)
	}

	chartout, err := Package(chartSkaffoldDir, "./", version, version)
	if err != nil {
		Logger.Error("unable to helm package the charts folder", zap.Error(err))
		panic(err)
	}

	err = HelmPush(*defaultConfig.FgHelmRepoUrl, *defaultConfig.HelmRepoUser, *defaultConfig.HelmRepoPassword, chartout)
	if err != nil {
		Logger.Error("unable to push the helm chart to repo", zap.Error(err))
		panic(err)
	}

	if defaultConfig.OutputNotesPath != "" {
		err = WriteBuildNotes(defaultConfig.OutputNotesPath, BuildNotes(appname, version, repoUrl, dockertag, *defaultConfig.FgHelmRepoUrl, appname, version))
		if err != nil {
			Logger.Error("unable to write output notes to file", zap.String("file", defaultConfig.OutputNotesPath), zap.Error(err))
			panic(err)
		}
	}

	fmt.Printf(string(colorGreen)+finalOutputString+string(colorReset), appname, version, dockertag, *defaultConfig.FgHelmRepoUrl)
}

func worker(finished chan error, url, outputfile string) {
	_, err := DownloadFile(url, outputfile)
	finished <- err
}
