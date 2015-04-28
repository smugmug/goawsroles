goawsroles
==========

`goawsroles` provides an interface and sample implementations for safe handling of AWS
credentials. While typically used with the `godynamo` package (https://github.com/smugmug/godynamo),
it is useful on its own and should be easy to integrate into any package requiring a
consistent interface for AWS credentials.

Typically, AWS credentials consist of a AccessKey, Secret and optionally a Token if
temporary credentials are used. We want to be able to safely update these and access
them in programs. It is useful to have a variety of mechanisms for sourcing these credentials -
hardcoded, environment variables, or local files. `goawsroles` seeks to provide one interface
for these and other scenarios, with the goal being safe access to read and update credential data.

At SmugMug, our typical use involves local files in `/etc` for each of the AccessKey, Secret
and Token. These are updated by another process every thirty minutes. Local files provide
for ease-of-use with some decent security via user and group permissions that are more
effective than environment-variable based solutions.  The `RolesFiles`
implementation included here provides a solution for this scenario; it includes a
`RolesWatch` method which, when launched via a goroutine, will watch the local
permissions files for updates. When all three files are updated within a sane time
interval, the internal representation of the permission strings for the AccessKey,
Secret and Token will be updated. Using this mechanism along with another process
to keep our local files updated and valid, we can be sure that any time we call
the `Get` method on the `RolesFiles` instance, we are getting fresh credentials.

### Example

This example is contained within the unit test for the `RolesFiles` instance, with
some extra comments.

        func TestRolesWatcher(t *testing.T) {

            // This roles instance reads from files
            rw := NewRolesFiles()

            // This is where our external process would place files containing
            // credential data retrieved from AWS.
            rw.BaseDir = "./test_files"

            // The files underneath the BaseDir for the respective credential parts.
            rw.AccessKeyFile = "role_access_key"
            rw.SecretFile = "role_secret_key"
            rw.TokenFile = "role_token"

            // We want to read the credential data once to make sure we can do
            // so correctly in the foreground.
            rw_err := rw.RolesRead()
            if rw_err != nil {
                t.Errorf("roles read err")
            }

            // We are about to launch our file watcher in the background. Once launched,
            // the var `rw` will be considered to always have the newest credential information.

            // `c` is a channel for the RolesWatcher to send errors on
            c := make(chan error)
            // `s` is a channel for the RolesWatcher to tell us when it has refreshed credentials.
            s := make(chan bool)

            go rw.RolesWatch(c, s)

            go func() {
                for {
                    select {
                        // This case tells us the files have been re-read
                        case <-s:
                            fmt.Printf("\n*********** re-read the files\n")
                            accessKey, secret, token, get_err := rw.Get()
                            if get_err != nil {
                                e := fmt.Sprintf("cannot get a role file:%s\n", get_err.Error()
                                t.Errorf(e)
                            } else {
                                fmt.Printf("new data\naccess key:%s\nsecret:%s\ntoken:%s\n",
                                           accessKey, secret, token)
                            }
                        // We want to short-circuit the test after five seconds
                        case <-time.After(5 * time.Second):
                            fmt.Printf("exiting watcher loop\n")
                            c <- nil
                    }
                }
            }()

            // Give the RolesWatcher a second to start watching files.
            time.Sleep(1 * time.Second)
            // Now we want to touch our files to change their timestamp, which should
            // trigger the RolesWatcher to re-read them, which will then cause a message
            // to be sent on the `s` channel above.
            touch_cmd1 := exec.Command("touch",rw.BaseDir + string(filepath.Separator) + rw.AccessKeyFile)
            touch_cmd2 := exec.Command("touch",rw.BaseDir + string(filepath.Separator) + rw.SecretFile)
            touch_cmd3 := exec.Command("touch",rw.BaseDir + string(filepath.Separator) + rw.TokenFile)
            touch_err1 := touch_cmd1.Run()
            if touch_err1 != nil {
                t.Errorf(touch_err1.Error())
            }
            touch_err2 := touch_cmd2.Run()
            if touch_err2 != nil {
                t.Errorf(touch_err2.Error())
            }
            touch_err3 := touch_cmd3.Run()
            if touch_err3 != nil {
                t.Errorf(touch_err3.Error())
            }
            time.Sleep(2 * time.Second)

            // If this is triggered, then it means something went wrong reading the credentials files.
            watch_err := <-c
            if watch_err != nil {
                e := fmt.Sprintf("error from watcher: %s\n", watch_err.Error())
                t.Errorf(e)
            }
        }


The `RolesMaster` instance is less interesting. This instance of the `RolesReader` interface only
accepts a one-time initialization of the AccessKey and Secret. Since "master" credentials do
not contain a Token, it is forced to be empty.

### Installation

        go get github.com/smugmug/goawsroles/roles_files
        go get github.com/smugmug/goawsroles/roles_master

### Dependencies

This package depends on the still-develop "official" AWS SDK for Go at

        github.com/awslabs/aws-sdk-go/aws

This package changes often so you may need to update it directly if you have build issues with goawsroles.

### Contact Us

Please contact opensource@smugmug.com for information related to this package.
Pull requests also welcome!
