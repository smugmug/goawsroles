goawsroles
==========

`goawsroles` provides an interface and single implementation to assist in the handling of Amazon AWS IAM roles
credentials.

Please see Amazon AWS documentation for an explanation of IAM.

This package will be loaded as a dependency for `godynamo` (https://github.com/smugmug/godynamo).

The purpose of this package is to provide an interface and common implementations for
managing credentials and safely using them in programs. By "credentials", we mean
the AccessKey,Secret and Token used to authenticate requests. These may be "master"
credentials or temporary credentials (IAM) that must be safely refreshed in running
programs.

See `roles_files/roles_files_test.go` for a working test that reflects a useful scenario:
using an out-of-band process to manage local files that are valid IAM temporary credentials,
and using a Roles instance to "watch" these files for changes that can be atomically updated
and safely used in a program.

There are alternate techniques used by other packages and SDKs for managing credentials,
and goawsroles attempts to accommodate these. The "Credentials" method can be used for
exporting credential data in a format compatible with what is currently projected
to be the struct used in the "official" AWS Go SDK.

### Installation

        go get github.com/smugmug/goawsroles/roles_files

### Contact Us

Please contact opensource@smugmug.com for information related to this package.
Pull requests also welcome!
