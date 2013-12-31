// Copyright (c) 2013,2014 SmugMug, Inc. All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
//       copyright notice, this list of conditions and the following
//       disclaimer in the documentation and/or other materials provided
//       with the distribution.
// 
// THIS SOFTWARE IS PROVIDED BY SMUGMUG, INC. ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL SMUGMUG, INC. BE LIABLE FOR
// ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
// GOODS OR SERVICES;LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
// IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package roles_files

import (
	"testing"
	"fmt"
	roles "github.com/smugmug/goawsroles/roles"
)

func TestRolesFiles(t *testing.T) {
	rf_ := NewRolesFiles()
	if !rf_.IsEmpty() {
		t.Errorf("new RolesFile is not empty?")
	}
	rf_.BaseDir       = "/etc/tags"
	rf_.AccessKeyFile = "role_access_key"
	rf_.SecretFile    = "role_secret_key"
	rf_.TokenFile     = "role_token"
	rf := roles.RolesReader(rf_)
	rr_err := rf.RolesRead()
	if rr_err != nil {
		t.Errorf(rr_err.Error())
	}
	access_key,access_key_err := rf.GetAccessKey()
	if access_key_err != nil {
		t.Errorf("cannot read access key?")
	} else {
		fmt.Printf("access key: %s\n",access_key)
	}
	secret,secret_err := rf.GetSecret()
	if secret_err != nil {
		t.Errorf("cannot read access key?")
	} else {
		fmt.Printf("secret: %s\n",secret)
	}
	token,token_err := rf.GetToken()
	if token_err != nil {
		t.Errorf("cannot read access key?")
	} else {
		fmt.Printf("token: %s\n",token)
	}

	// now unset the token file, which should cause all of our entries to be zero'd
	rf_.TokenFile = ""
	rf = roles.RolesReader(rf_)
	rr_err = rf.RolesRead()
	if rr_err == nil {
	 	t.Errorf("no err on unset token file?")
	}
	rf_.BaseDir       = "/etc/tags"
	rf_.AccessKeyFile = "role_access_key"
	rf_.SecretFile    = "role_secret_key"
	rf_.TokenFile     = "role_token"
	rf = roles.RolesReader(rf_)

	// this will cause your program to appear to hang, you can comment the rest out to get a
	// completed test
	c := make(chan error)
	s := make(chan bool)
	go rf.RolesWatch(c,s)

	go func() {
		for {
			select {
			case <- s:
				fmt.Printf("*********** re-read the files\n")
				accessKey,secret,token,get_err := rf.Get()
				if get_err != nil {
					fmt.Printf("cannot get a role file:%s\n",get_err.Error())
				} else {
					fmt.Printf("access key:%s\nsecret:%s\ntoken:%s\n",
						accessKey,secret,token)
				}
			}
		}
	}()

	watch_err := <- c
	if watch_err != nil {
		fmt.Printf("error from watcher: %s\n",watch_err.Error())
	}

}
