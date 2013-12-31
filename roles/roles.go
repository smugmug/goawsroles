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

// Defines an interface that can be implemented to provide IAM Roles data through various communication
// mechanisms, most likely regular text files (see the roles_files.go implementation).
package roles

type RolesFields struct {
	AccessKey string
	Secret string
	Token string
}

// NewRolesFields returns a pointer to a RolesFields instance.
func NewRolesFields() (*RolesFields) {
	return new(RolesFields)
}

// IsEmpty determines if a RolesField struct is uninitialized.
func (rf *RolesFields) IsEmpty() (bool) {
	return rf.AccessKey == "" || rf.Secret == "" || rf.Token == ""
}

// ZeroRoles recreate the RolessFields as initialized by NewRolesFields.
func (rf *RolesFields) ZeroRoles() {
	rf.AccessKey = ""
	rf.Secret    = ""
	rf.Token     = ""
}

// RolesReader is our interface to describe the functionality for roles credential information.
type RolesReader interface {
	// blocking read of roles from roles provider
	RolesRead() (error)
	// zero out roles values
	ZeroRoles()
	// test for emptiness
	IsEmpty() (bool)
	// getters
	// wrapper to individual getters
	Get() (string,string,string,error)
	// below funcs should be called by GetAllRoles
	GetAccessKey() (string,error)
	GetSecret() (string,error)
	GetToken() (string,error)
	// mechanism by which roles strings can be refreshed (event-based, polling etc).
	// if you don't want to implement this, just use it to wrap RolesRead
	RolesWatch(c chan error,s chan bool)
}
