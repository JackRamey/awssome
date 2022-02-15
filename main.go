package main

import (
	"fmt"
	"os/exec"
	"time"
)

func main() {
	awsCfg := LoadAWSConfig()
	awsCreds := LoadAWSCredentials()

	loginRequired := true
	cache := readSSOCache()
	if cache != nil {
		loginExpiresAt, err := time.Parse(time.RFC3339, cache.ExpiresAt)
		checkErr(err)
		loginRequired = loginExpiresAt.Before(time.Now())
	}

	if loginRequired {
		for profileName, profile := range awsCfg.Profiles {
			if profile.SSOEnabled {
				fmt.Printf("logging in with profile %s\n", profileName)
				executeLogin(profileName)
				break
			}
		}
		cache = readSSOCache()
	}

	for profileName, profile := range awsCfg.Profiles {
		roleCreds := getRoleCredentials(profile, *cache)
		if cred, ok := awsCreds.Credentials[profileName]; ok {
			roleCreds.section = cred.section
		} else {
			var err error
			roleCreds.section, err = awsCreds.file.NewSection(profileName)
			checkErr(err)
		}
	}

	awsCfg.Save()
	awsCreds.Save()
}

func executeLogin(profile string) {
	loginCmd := exec.Command("aws", "sso", "login", "--profile", profile)
	stdOut, err := loginCmd.Output()
	checkErr(err)
	fmt.Println(string(stdOut))
}

func must(str string, err error) string {
	if err != nil {
		panic(err)
	}
	return str
}
