package build

import (
	"encoding/json"
	"fmt"
)

type BuildConfig struct {
	ID                string
	ECRRegion         *string `json:"ecr-region,omitempty"`
	ECRAccessKey      *string `json:"ecr-access-key,omitempty"`
	ECRSecret         *string `json:"ecr-secret,omitempty"`
	ECRRegistryID     *string `json:"ecr-ergistry-id,omitempty"`
	FgECRRegion         *string `json:"fg-ecr-region,omitempty"`
	FgECRAccessKey      *string `json:"fg-ecr-access-key,omitempty"`
	FgECRSecret         *string `json:"fg-ecr-secret,omitempty"`
	FgECRRegistryID     *string `json:"fg-ecr-ergistry-id,omitempty"`
	HelmBasePath      *string `json:"helm-base-path,omitempty"`
	HelmRepoUrl       *string `json:"helm-repo-url,omitempty"`
	FgHelmRepoUrl       *string `json:"fg-helm-repo-url,omitempty"`
	InfraUserKey      *string `json:"infra-user-key,omitempty"`
	HelmRepoUser      *string `json:"helm-repo-user,omitempty"`
	HelmRepoPassword  *string `json:"helm-repo-password,omitempty"`
	Dockerfile        *string `json:"dockerfile,omitempty"`
	AppName           string
	BuildID           string
	VersionTag        string
	BuildCommitSha    string
	Version           string
	HelmValueOverride string
	OutputNotesPath   string
}

func (b *BuildConfig) Prepare() error {
	// now := time.Now()
	// nowinsec := strconv.Itoa(int(now.Unix()))
	if b.AppName == "" {
		return fmt.Errorf("AppName cannot be empty")
	}

	// if b.BuildID == "" {
	// 	b.BuildID = nowinsec
	// }
	b.Version = b.VersionTag
	// switch b.VersionScheme {
	// case "short":
	// 	b.Version = b.VersionTag
	// case "long":
	// 	sep := "-"
	// 	b.Version = b.VersionTag
	// 	if b.VersionExtra != "" {
	// 		b.Version = b.Version + sep + b.VersionExtra
	// 		sep = "."
	// 	}
	// 	b.Version = b.Version + sep + b.BuildID
	// default:
	// 	return fmt.Errorf("%s version scheme not supported, only long and short is supported", b.VersionScheme)
	// }
	return nil
}

func (b *BuildConfig) String() string {
	j, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err.Error()
	}

	return string(j)
}
