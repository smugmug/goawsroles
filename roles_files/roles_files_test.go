package roles_files

import (
	"fmt"
	roles "github.com/smugmug/goawsroles/roles"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestRolesFiles(t *testing.T) {
	rf_ := NewRolesFiles()
	if !rf_.IsEmpty() {
		t.Errorf("new RolesFile is not empty?")
	}
	rf_.BaseDir = "./test_files"
	rf_.AccessKeyFile = "role_access_key"
	rf_.SecretFile = "role_secret_key"
	rf_.TokenFile = "role_token"
	rf := roles.RolesReader(rf_)
	rr_err := rf.RolesRead()
	if rr_err != nil {
		t.Errorf(rr_err.Error())
	}
	access_key, access_key_err := rf.GetAccessKey()
	if access_key_err != nil {
		t.Errorf("cannot read access key?")
	} else {
		fmt.Printf("access key: %s\n", access_key)
	}
	secret, secret_err := rf.GetSecret()
	if secret_err != nil {
		t.Errorf("cannot read secret?")
	} else {
		fmt.Printf("secret: %s\n", secret)
	}
	token, token_err := rf.GetToken()
	if token_err != nil {
		t.Errorf("cannot read token?")
	} else {
		fmt.Printf("token: %s\n", token)
	}

	// now unset the token file, which should cause all of our entries to be zero'd
	rf_.TokenFile = ""
	rf = roles.RolesReader(rf_)
	rr_err = rf.RolesRead()
	if rr_err == nil {
		t.Errorf("roles read err")
	}
}

func TestRolesWatcher(t *testing.T) {
	rw := NewRolesFiles()
	if !rw.IsEmpty() {
		t.Errorf("new RolesFile is not empty?")
	}
	rw.BaseDir = "./test_files"
	rw.AccessKeyFile = "role_access_key"
	rw.SecretFile = "role_secret_key"
	rw.TokenFile = "role_token"
	rw_err := rw.RolesRead()
	if rw_err != nil {
		fmt.Printf("roles read err: %s\n", rw_err.Error())
		t.Errorf("roles read err")
	}

	c := make(chan error)
	s := make(chan bool)
	go rw.RolesWatch(c, s)

	go func() {
		for {
			select {
			case <-s:
				fmt.Printf("\n*********** re-read the files\n")
				accessKey, secret, token, get_err := rw.Get()
				if get_err != nil {
					e := fmt.Sprintf("cannot get a role file:%s\n", get_err.Error())
					t.Errorf(e)
				} else {
					fmt.Printf("new data\naccess key:%s\nsecret:%s\ntoken:%s\n",
						accessKey, secret, token)
				}
			case <-time.After(5 * time.Second):
				fmt.Printf("exiting watcher loop\n")
				c <- nil
			}
		}
	}()

	time.Sleep(1 * time.Second)
	touch_cmd1 := exec.Command("touch", rw.BaseDir+string(filepath.Separator)+rw.AccessKeyFile)
	touch_cmd2 := exec.Command("touch", rw.BaseDir+string(filepath.Separator)+rw.SecretFile)
	touch_cmd3 := exec.Command("touch", rw.BaseDir+string(filepath.Separator)+rw.TokenFile)
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

	watch_err := <-c
	if watch_err != nil {
		e := fmt.Sprintf("error from watcher: %s\n", watch_err.Error())
		t.Errorf(e)
	}
}

func TestMissingRolesFiles(t *testing.T) {
	rf_ := NewRolesFiles()
	if !rf_.IsEmpty() {
		t.Errorf("new RolesFile is not empty?")
	}
	rf_.BaseDir = "./test_files_not_there"
	rf_.AccessKeyFile = "role_access_key"
	rf_.SecretFile = "role_secret_key"
	rf_.TokenFile = "role_token"
	rf := roles.RolesReader(rf_)
	rr_err := rf.RolesRead()
	if rr_err == nil {
		t.Errorf(rr_err.Error())
	}
}
