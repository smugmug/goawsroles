// Implements the RolesReader interface (roles.go) for the simplest case - a safe data structure
// for storing the AccessKey, Secret and Token. Identical to RolesMaster except this allows
// the token to be set. If in doubt or in need of the most flexibility and fewest surprises, use this.
//
package roles_simple

import (
	"errors"
	sdk_credentials "github.com/awslabs/aws-sdk-go/aws"
	roles "github.com/smugmug/goawsroles/roles"
	"sync"
)

const (
	ROLE_PROVIDER = "simple"
)

// RolesSimple is populated directly once from master credentials
type RolesSimple struct {
	roleFields *roles.RolesFields
	lock       sync.RWMutex
}

// NewRolesSimple returns a pointer to a RolesSimple instance.
func NewRolesSimple(accessKey, secret, token string) *RolesSimple {
	r := new(RolesSimple)
	r.roleFields = roles.NewRolesFields()
	r.roleFields.AccessKey = accessKey
	r.roleFields.Secret = secret
	r.roleFields.Token = token
	return r
}

// ProviderType is a descriptive string of the implementation.
func (rf *RolesSimple) ProviderType() string {
	return ROLE_PROVIDER
}

// UsingIAM tells us if the credentials provided by this role are temporary credentials which
// also have a Token component, or if they are durable key/secret-only credentials.
func (rf *RolesSimple) UsingIAM() bool {
	return false
}

// IsEmpty determines if a RolesSimple struct is uninitialized.
func (rf *RolesSimple) IsEmpty() bool {
	return rf.roleFields.IsEmpty()
}

// ZeroRoles recreate the RolesSimple as initialized by NewRolesSimple
func (rf *RolesSimple) ZeroRoles() {
	rf.lock.Lock()
	rf.roleFields.ZeroRoles()
	rf.lock.Unlock()
}

// RolesRead is a no-op here since RolesSimple is immutable after its initial setting.
func (rf *RolesSimple) RolesRead() error {
	return nil
}

// RolesWatch will panic on this implementation as master credentials are immutable.
func (rf *RolesSimple) RolesWatch(err_chan chan error, read_signal chan bool) {
	panic("RolesWatch not defined for RolesSimple as credentials are immutable")
}

// Get returns the (accessKey,secret,token), or an error.
func (rf *RolesSimple) Get() (string, string, string, error) {
	rf.lock.RLock()
	defer rf.lock.RUnlock()
	secret := ""
	if rf.roleFields.Secret == "" {
		return "", "", "", errors.New("roles_simple.Get: empty Secret")
	} else {
		secret = rf.roleFields.Secret
	}
	accessKey := ""
	if rf.roleFields.AccessKey == "" {
		return "", "", "", errors.New("roles_simple.Get: empty AccessKey")
	} else {
		accessKey = rf.roleFields.AccessKey
	}
	token := ""
	if rf.roleFields.Token == "" {
		return "", "", "", errors.New("roles_simple.Get: empty Token")
	} else {
		token = rf.roleFields.Token
	}
	return accessKey, secret, token, nil
}

// GetAccessKey returns the accessKey or an error.
func (rf *RolesSimple) GetAccessKey() (string, error) {
	rf.lock.RLock()
	defer rf.lock.RUnlock()
	if rf.roleFields.AccessKey == "" {
		return "", errors.New("roles_simple.GetAccessKey: empty AccessKey")
	} else {
		return rf.roleFields.AccessKey, nil
	}
}

// GetSecret returns the secret or an error.
func (rf *RolesSimple) GetSecret() (string, error) {
	rf.lock.RLock()
	defer rf.lock.RUnlock()
	if rf.roleFields.Secret == "" {
		return "", errors.New("roles_simple.GetSecret: empty Secret")
	} else {
		return rf.roleFields.Secret, nil
	}
}

// GetToken returns the token or an error.
func (rf *RolesSimple) GetToken() (string, error) {
	rf.lock.RLock()
	defer rf.lock.RUnlock()
	if rf.roleFields.Token == "" {
		return "", errors.New("roles_simple.GetToken: empty Token")
	} else {
		return rf.roleFields.Token, nil
	}
}

// Credentials will expose the Role as a sdk Credential.
func (rf *RolesSimple) Credentials() (*sdk_credentials.Credentials, error) {
	accessKey, secret, token, get_err := rf.Get()
	if get_err != nil {
		return nil, get_err
	}
	return &sdk_credentials.Credentials{
		AccessKeyID:     accessKey,
		SecretAccessKey: secret,
		SessionToken:    token}, nil
}
