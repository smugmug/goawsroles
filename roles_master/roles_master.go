// Implements the RolesReader interface (roles.go) for text files containing master access key and secret.
//
package roles_master

import (
	"errors"
	roles "github.com/smugmug/goawsroles/roles"
	"sync"
)

const (
	ROLE_PROVIDER = "master"
)

// RolesMaster is populated directly once from master credentials
type RolesMaster struct {
	roleFields *roles.RolesFields
	lock       sync.RWMutex
}

// NewRolesMaster returns a pointer to a RolesMaster instance.
func NewRolesMaster(accessKey, secret string) *RolesMaster {
	r := new(RolesMaster)
	r.roleFields = roles.NewRolesFields()
	r.roleFields.AccessKey = accessKey
	r.roleFields.Secret = secret
	return r
}

// NewRolesMasterCredentials returns a pointer to a RolesMaster instance.
func NewRolesMasterCredentials(accessKey, secret string) *RolesMaster {
	return NewRolesMaster(accessKey, secret)
}

// ProviderType is a descriptive string of the implementation.
func (rf *RolesMaster) ProviderType() string {
	return ROLE_PROVIDER
}

// UsingIAM tells us if the credentials provided by this role are temporary credentials which
// also have a Token component, or if they are durable key/secret-only credentials.
func (rf *RolesMaster) UsingIAM() bool {
	return false
}

// IsEmpty determines if a RolesMaster struct is uninitialized.
func (rf *RolesMaster) IsEmpty() bool {
	return rf.roleFields.IsEmpty()
}

// ZeroRoles recreate the RolesMaster as initialized by NewRolesMaster
func (rf *RolesMaster) ZeroRoles() {
	rf.lock.Lock()
	rf.roleFields.ZeroRoles()
	rf.lock.Unlock()
}

// RolesRead is a no-op here since RolesMaster is immutable after its initial setting.
func (rf *RolesMaster) RolesRead() error {
	return nil
}

// RolesWatch will panic on this implementation as master credentials are immutable.
func (rf *RolesMaster) RolesWatch(err_chan chan error, read_signal chan bool) {
	panic("RolesWatch not defined for RolesMaster as credentials are immutable")
}

// Get returns the (accessKey,secret,token), or an error.
func (rf *RolesMaster) Get() (string, string, string, error) {
	rf.lock.RLock()
	defer rf.lock.RUnlock()
	secret := ""
	if rf.roleFields.Secret == "" {
		return "", "", "", errors.New("roles_master.Get: empty Secret")
	} else {
		secret = rf.roleFields.Secret
	}
	accessKey := ""
	if rf.roleFields.AccessKey == "" {
		return "", "", "", errors.New("roles_master.Get: empty AccessKey")
	} else {
		accessKey = rf.roleFields.AccessKey
	}
	return accessKey, secret, "", nil
}

// GetAccessKey returns the accessKey or an error.
func (rf *RolesMaster) GetAccessKey() (string, error) {
	rf.lock.RLock()
	defer rf.lock.RUnlock()
	if rf.roleFields.AccessKey == "" {
		return "", errors.New("roles_master.GetAccessKey: empty AccessKey")
	} else {
		return rf.roleFields.AccessKey, nil
	}
}

// GetSecret returns the secret or an error.
func (rf *RolesMaster) GetSecret() (string, error) {
	rf.lock.RLock()
	defer rf.lock.RUnlock()
	if rf.roleFields.Secret == "" {
		return "", errors.New("roles_master.GetSecret: empty Secret")
	} else {
		return rf.roleFields.Secret, nil
	}
}

// GetToken returns an empty string as master credentials do not have a Token
func (rf *RolesMaster) GetToken() (string, error) {
	return "", errors.New("roles_master.GetToken: master roles do not use Tokens")
}
