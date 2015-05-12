// Defines an interface that can be implemented to provide IAM Roles data through various communication
// mechanisms, most likely regular text files (see the roles_files.go implementation).
package roles

type RolesFields struct {
	AccessKey string
	Secret    string
	Token     string
}

// NewRolesFields returns a pointer to a RolesFields instance.
func NewRolesFields() *RolesFields {
	return new(RolesFields)
}

// IsEmpty determines if a RolesField struct is uninitialized.
func (rf *RolesFields) IsEmpty() bool {
	return rf.AccessKey == "" || rf.Secret == "" || rf.Token == ""
}

// ZeroRoles recreate the RolessFields as initialized by NewRolesFields.
func (rf *RolesFields) ZeroRoles() {
	rf.AccessKey = ""
	rf.Secret = ""
	rf.Token = ""
}

// RolesReader is our interface to describe the functionality for roles credential information.
type RolesReader interface {

	// a textual description for an instantiating package.
	// in the case of the instantiating packages provided, I use a const ROLES_PROVIDER.
	ProviderType() string
	// UsingIAM tells us if the credentials provided by this role are temporary credentials which
	// also have a Token component, or if they are durable accesskey/secret-only credentials.
	UsingIAM() bool
	// blocking read of roles from roles provider
	RolesRead() error
	// zero out roles values
	ZeroRoles()
	// test for emptiness
	IsEmpty() bool

	// getters
	// wrapper to individual getters
	Get() (string, string, string, error)

	// below funcs should be called by GetAllRoles
	GetAccessKey() (string, error)
	GetSecret() (string, error)
	GetToken() (string, error)

	// Any activity that is required to observe, validate, or refresh
	// roles out-of-band.
	// The chan 'c' can be used to signal abnormal states, while 's' can
	// be used to signal normal operation. Packages instantiating this
	// interface may panic if there is no out-of-band updating defined.
	RolesWatch(c chan error, s chan bool)
}
