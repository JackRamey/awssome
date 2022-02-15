# AWSSOME

Apparently there are still problems when trying to use the AWS branded SSO with third
party deploy tools like Serverless. This tool aims to make CLI access
to AWS a little bit easier with AWS SSO.

Make sure you configure at least one profile with AWS SSO.

You can do that by following the instructions [here](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html).

You only need to configure one profile to have all of the SSO values required in the setup,
all the others only need to have the `sso_account_id` and `sso_role_name` set.

Once you have your `~/.aws/config` file set up.

Run it!
```
awssome
```

`awssome` will check to see if you have an active AWS session, and if not, will prompt you to login through your default
browser. Once logged in, it will automatically populate your `~/.aws/credentials` file with the required values for
using your preferred third party tool for interacting with AWS.
