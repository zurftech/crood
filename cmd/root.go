/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/zurftech/crood/pkg/build"
	"go.uber.org/zap"

	"github.com/emirpasic/gods/maps/linkedhashmap"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	// The name of our config file, without the file extension because viper supports many different config file languages.
	defaultConfigFilename = "crood"

	// The environment variable prefix of all environment variables bound to our command line flags.
	// For example, --number is bound to STING_NUMBER.
	envPrefix = "CR"
)

var logger *zap.Logger
var config *build.BuildConfig
var configPath *[]string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "build-system",
	Short: "A brief description of your application",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// You can bind cobra and viper in a few locations, but PersistencePreRunE on the root command works well
		build.Logger = logger
		limap, err := loadRemoteConfig(*configPath)
		if err != nil {
			logger.Error("unable to load from remote", zap.Error(err))
			return err
		}
		_, err = initializeConfig(cmd, limap)
		if err != nil {
			logger.Error("unable to load from remote", zap.Error(err))
			return err
		}
		return nil
	},
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) {
		build.Build(config)
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	logger, _ = zap.NewProduction()
	defer logger.Sync()
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	//dynamodb://a:pass@ap-southeast-1/buildConfig
	f := rootCmd.Flags()
	config = &build.BuildConfig{}
	configPath = f.StringArrayP("config-file", "f", []string{"./"}, "multiple config files to load, all configs are merged to left")
	config.ECRAccessKey = f.String("ecr-access-key", "", "configure the aws key to access ecr")
	config.ECRRegion = f.String("ecr-region", "", "configure aws region for ecr")
	config.ECRRegistryID = f.String("ecr-registry-id", "", "configure aws ecr registry id to use, default will be account default")
	config.ECRSecret = f.String("ecr-secret", "", "configure aws secret for ecr")
	config.HelmBasePath = f.String("helm-base-path", "", "helm repo to use as a base")
	config.HelmRepoUrl = f.String("helm-repo-url", "", "helm repo url to upload the final packaged chart")
	config.InfraUserKey = f.String("infra-user-key", "", "infra user key to access bitbucket other repositories")
	config.HelmRepoUser = f.String("helm-repo-user", "", "user for accessing helm repo")
	config.HelmRepoPassword = f.String("helm-repo-password", "", "password for accessing helm repo")
	config.Dockerfile = f.StringP("docker-file", "d", "Dockerfile", "docker file path")
	f.StringVarP(&config.AppName, "app-name", "a", "", "the name of the app you are building")
	f.StringVarP(&config.BuildID, "build-id", "b", "", "a unique id/number representing this build, defaults to epoch seconds")
	f.StringVarP(&config.VersionTag, "version-tag", "t", "0.0.0", "last tagged main version id ex: 1.0.0, 1.0.2 etc, default, 0.0.0")
	f.StringVarP(&config.HelmValueOverride, "helm-values-override", "o", "", "a value file which will get overriden with the base helm chart values.yaml")
	f.StringVarP(&config.OutputNotesPath, "output-notes-path", "", "", "a path where the build results are written as key values")
	rootCmd.MarkFlagRequired("app-name")
}

func loadRemoteConfig(configs []string) (*linkedhashmap.Map, error) {
	loadedConfigsInOrder := linkedhashmap.New()
	if configs == nil {
		fmt.Println("empty file paths to load")
		return loadedConfigsInOrder, nil
	}

	loadedConfigs := make(map[string]string)

	for _, el := range configs {
		u, err := url.Parse(el)
		if err != nil {
			return nil, err
		}
		resourceIdsRaw := u.Query().Get("id")
		resourceIds := strings.Split(strings.Trim(resourceIdsRaw, " "), ",")
		resourceToFetch := []string{}

		for _, el := range resourceIds {
			if _, ok := loadedConfigs[el]; !ok {
				resourceToFetch = append(resourceToFetch, el)
				loadedConfigs[el] = ""
			} else {
				logger.Info("this config is already laoded", zap.String("key", el))
			}
		}

		if len(resourceToFetch) < 1 {
			logger.Info("there not many resources to fetch from this config", zap.String("path", el))
			continue
		}

		// region, _, _ := net.SplitHostPort(u.Host)
		region := u.Host
		pass, _ := u.User.Password()
		//Check for password existance

		logger.Info("parsed url elments",
			zap.String("region", region),
			zap.String("password", pass),
			zap.String("user", u.User.Username()),
			zap.String("query", u.RawQuery),
			zap.String("resource", strings.Trim(u.Path, "/")),
			zap.Strings("resourceIds", resourceIds),
			zap.String("host", u.Host),
		)
		switch u.Scheme {
		case "dynamodb":
			fmt.Printf("%s   %s  %s   %s %s\n", u.RawQuery, u.Path, u.User.Username(), pass, u.Host)
			sess, err := build.AwsSession(region, u.User.Username(), pass)
			if err != nil {
				logger.Error(err.Error())
				return nil, err
			}

			resp, err := build.LoadConfig(sess, strings.Trim(u.Path, "/"), resourceToFetch)
			if err != nil {
				logger.Error(err.Error())
				return nil, err
			}

			for key, el := range resp {
				d, err := json.MarshalIndent(el, "", "  ")
				if err != nil {
					return nil, err
				}

				fileDir := fmt.Sprintf("/tmp/dynamicConfig/%s", key)
				filePath := fmt.Sprintf("%s/%s.json", fileDir, defaultConfigFilename)
				err = os.MkdirAll(fileDir, 0755)
				if err != nil {
					logger.Error("unable to create folder", zap.String("dir", fileDir))
					return nil, err
				}
				// _, err = f.Write(d)
				err = os.WriteFile(filePath, d, 0755)
				if err != nil {
					logger.Error("unable to write to file")
					return nil, err
				}
				loadedConfigsInOrder.Put(key, fileDir)
			}

		default:
			return nil, fmt.Errorf("configs using %s scheme not implemented", u.Scheme)
		}
	}
	return loadedConfigsInOrder, nil
}

func getViperConfigs(path string) (*viper.Viper, error) {
	v := viper.New()
	v.SetConfigName(defaultConfigFilename)
	v.AddConfigPath(path)
	if err := v.ReadInConfig(); err != nil {
		// It's okay if there isn't a config file
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
		logger.Info("unable to load config files from path", zap.String("path", path))
	}
	return v, nil
}

func initializeConfig(cmd *cobra.Command, limap *linkedhashmap.Map) (*viper.Viper, error) {
	v := viper.New()
	v.SetEnvPrefix(envPrefix)

	it := limap.Iterator()
	for it.Next() {
		key, value := it.Key(), it.Value()
		path := fmt.Sprint(value)
		logger.Info("reading config using viper from path", zap.String("key", key.(string)), zap.String("path", path))
		vn, err := getViperConfigs(path)
		if err != nil {
			return nil, err
		}
		v.MergeConfigMap(vn.AllSettings())
	}

	vx, err := getViperConfigs("./")
	if err != nil {
		return nil, err
	}
	v.MergeConfigMap(vx.AllSettings())

	// Bind to environment variables
	// Works great for simple config names, but needs help for names
	// like --favorite-color which we fix in the bindFlags function
	v.AutomaticEnv()

	// Bind the current command's flags to viper
	bindFlags(cmd, v)
	return v, nil
}

// Bind each cobra flag to its associated viper configuration (config file and environment variable)
func bindFlags(cmd *cobra.Command, v *viper.Viper) {
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		// Environment variables can't have dashes in them, so bind them to their equivalent
		// keys with underscores, e.g. --favorite-color to STING_FAVORITE_COLOR
		if strings.Contains(f.Name, "-") {
			envVarSuffix := strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
			v.BindEnv(f.Name, fmt.Sprintf("%s_%s", envPrefix, envVarSuffix))
		}

		// Apply the viper config value to the flag when the flag is not set and viper has a value
		if !f.Changed && v.IsSet(f.Name) {
			val := v.Get(f.Name)
			cmd.Flags().Set(f.Name, fmt.Sprintf("%v", val))
		}
	})
}
