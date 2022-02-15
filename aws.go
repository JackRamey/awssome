package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"

	"gopkg.in/ini.v1"
)

const (
	awsAccessKeyIDKey       = "aws_access_key_id"
	awsSecretAccessKeyKey   = "aws_secret_access_key"
	awsSessionTokenKey      = "aws_session_token"
	awsSessionExpirationKey = "aws_session_expiration"
	ssoAccountIDKey         = "sso_account_id"
	ssoStartURLKey          = "sso_start_url"
	ssoRoleNameKey          = "sso_role_name"
	ssoRegionKey            = "sso_region"
)

type AWSConfig struct {
	file     *ini.File
	Profiles map[string]Profile
}

type AWSCredentials struct {
	file        *ini.File
	Credentials map[string]AWSRoleCredentials
}

type Profile struct {
	section    *ini.Section
	Name       string
	AccountID  string
	RoleName   string
	StartUrl   string
	Region     string
	SSOEnabled bool
}

type AWSRoleCredentials struct {
	section         *ini.Section
	AccessKeyId     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"`
	SessionToken    string `json:"sessionToken"`
	Expiration      int    `json:"expiration"`
}

type awsCache struct {
	StartUrl    string `json:"startUrl"`
	AccessToken string `json:"accessToken"`
	ExpiresAt   string `json:"expiresAt"`
}

func LoadAWSConfig() AWSConfig {
	awsCfg, err := ini.Load(awsCfgPath())
	checkErr(err)

	profiles := make(map[string]Profile)
	for _, section := range awsCfg.Sections() {
		fields := strings.Fields(section.Name())

		// Looking only for profiles
		if len(fields) != 2 || fields[0] != "profile" {
			continue
		}

		profile := Profile{
			section:    section,
			Name:       fields[1],
			SSOEnabled: isProfileSSOEnabled(section),
		}

		if profile.SSOEnabled {
			accountIDKey, err := section.GetKey(ssoAccountIDKey)
			checkErr(err)
			profile.AccountID = accountIDKey.Value()

			roleNameKey, err := section.GetKey(ssoRoleNameKey)
			checkErr(err)
			profile.RoleName = roleNameKey.Value()

			regionKey, err := section.GetKey(ssoRegionKey)
			checkErr(err)
			profile.Region = regionKey.Value()

			startUrlKey, err := section.GetKey(ssoStartURLKey)
			checkErr(err)
			profile.StartUrl = startUrlKey.Value()
		}

		profiles[profile.Name] = profile
	}

	return AWSConfig{
		file:     awsCfg,
		Profiles: profiles,
	}
}

func (cfg *AWSConfig) Save() {
	checkErr(cfg.file.SaveTo(awsCfgPath()))
}

func LoadAWSCredentials() AWSCredentials {
	awsCreds, err := ini.Load(awsCredsPath())
	checkErr(err)

	//if !awsCreds.HasSection(defaultSectionKey) {
	//	_, err = awsCreds.NewSection(defaultSectionKey)
	//	checkErr(err)
	//}

	credentials := make(map[string]AWSRoleCredentials)
	for _, section := range awsCreds.Sections() {
		if section.Name() == ini.DefaultSection {
			continue
		}
		name := section.Name()
		var accessKeyId, secretAccessKey, sessionToken *ini.Key
		var expiration int
		if section.HasKey(awsAccessKeyIDKey) {
			accessKeyId, err = section.GetKey(awsAccessKeyIDKey)
			checkErr(err)
		}
		if section.HasKey(awsSecretAccessKeyKey) {
			secretAccessKey, err = section.GetKey(awsSecretAccessKeyKey)
			checkErr(err)
		}
		if section.HasKey(awsSessionTokenKey) {
			sessionToken, err = section.GetKey(awsSessionTokenKey)
			checkErr(err)
		}
		if section.HasKey(awsSessionExpirationKey) {
			expirationKey, err := section.GetKey(awsSessionExpirationKey)
			checkErr(err)
			expiration, err = expirationKey.Int()
			checkErr(err)
		}

		credentials[name] = AWSRoleCredentials{
			section:         section,
			AccessKeyId:     accessKeyId.Value(),
			SecretAccessKey: secretAccessKey.Value(),
			SessionToken:    sessionToken.Value(),
			Expiration:      expiration,
		}
	}

	return AWSCredentials{
		file:        awsCreds,
		Credentials: credentials,
	}
}

func (creds *AWSCredentials) Save() {
	for profileName, cred := range creds.Credentials {
		if cred.section == nil {
			section, err := creds.file.NewSection(profileName)
			checkErr(err)
			cred.section = section
		}

		if cred.section.HasKey(awsAccessKeyIDKey) {
			cred.section.DeleteKey(awsAccessKeyIDKey)
		}
		_, err := cred.section.NewKey(awsAccessKeyIDKey, cred.AccessKeyId)
		checkErr(err)

		if cred.section.HasKey(awsSecretAccessKeyKey) {
			cred.section.DeleteKey(awsSecretAccessKeyKey)
		}
		_, err = cred.section.NewKey(awsSecretAccessKeyKey, cred.SecretAccessKey)
		checkErr(err)

		if cred.section.HasKey(awsSessionTokenKey) {
			cred.section.DeleteKey(awsSessionTokenKey)
		}
		_, err = cred.section.NewKey(awsSessionTokenKey, cred.SessionToken)
		checkErr(err)

		if cred.section.HasKey(awsSessionExpirationKey) {
			cred.section.DeleteKey(awsSessionExpirationKey)
		}
		_, err = cred.section.NewKey(awsSessionExpirationKey, strconv.Itoa(cred.Expiration))
		checkErr(err)
		//t := time.Unix(int64(cred.Expiration), 0)
		//_, err = cred.section.NewKey(awsSessionExpirationKey, t.Format(time.RFC3339))
	}
	checkErr(creds.file.SaveTo(awsCredsPath()))
}

func readSSOCache() *awsCache {
	ssoCacheDir := path.Join(awsDir(), "sso", "cache")
	files, err := ioutil.ReadDir(ssoCacheDir)
	if err != nil {
		fmt.Println(err.Error())
		return nil
	}

	for _, file := range files {
		// We don't want the botocore file
		if strings.HasPrefix(file.Name(), "botocore") {
			continue
		}
		ssoCacheFile := path.Join(ssoCacheDir, file.Name())
		ssoCacheData, err := ioutil.ReadFile(ssoCacheFile)
		if err != nil {
			fmt.Println(err.Error())
			return nil
		}

		var ssoCache awsCache
		checkErr(json.Unmarshal(ssoCacheData, &ssoCache))
		return &ssoCache
	}

	return nil
}

func getRoleCredentials(profile Profile, cache awsCache) AWSRoleCredentials {
	getRoleCredentialsCmd := exec.Command("aws", "sso", "get-role-credentials",
		"--account-id", profile.AccountID,
		"--role-name", profile.RoleName,
		"--region", profile.Region,
		"--access-token", cache.AccessToken,
	)
	stdOut, err := getRoleCredentialsCmd.Output()
	checkErr(err)

	var output getRoleCredentialsOutput
	checkErr(json.Unmarshal(stdOut, &output))
	fmt.Println(profile.Name)
	fmt.Println(string(stdOut))
	return output.RoleCredentials
}

type getRoleCredentialsOutput struct {
	RoleCredentials AWSRoleCredentials `json:"roleCredentials"`
}

func awsCfgPath() string {
	return path.Join(awsDir(), "config")
}

func awsCredsPath() string {
	return path.Join(awsDir(), "credentials")
}

func awsDir() string {
	return path.Join(must(os.UserHomeDir()), ".aws")
}

func isProfileSSOEnabled(section *ini.Section) bool {
	return section.HasKey(ssoAccountIDKey) &&
		section.HasKey(ssoStartURLKey) &&
		section.HasKey(ssoRoleNameKey) &&
		section.HasKey(ssoRegionKey)
}
