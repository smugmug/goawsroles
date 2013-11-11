goawsroles
==========

`goawsroles` provides an interface and single implementation to assist in the handling of Amazon AWS IAM roles
credentials.

Please see Amazon AWS documentation for an explanation of IAM.

This package will be loaded as a dependency for `godynamo` (https://github.com/smugmug/godynamo).

The purpose of this package is to allow the seamless integration of IAM roles into running Go 
programs. An implementation is provided that reflects a common use case: role credential 
files retrieved by an external script that must be injected into a long-running Go program 
in a safe manner. Retrieval of IAM roles credentials is controlled by a long-running goroutine 
that will block until credentials have been fully updated locally. Presuming your ops staff
can arrange for IAM credential files to be deposited on your local system via automation, this package
will allow you to integrate IAM into your program such that your credentials will be refreshed 
automatically and safely.

See `roles_files/roles_files_test.go` for a working test that reflects this scenario.

### Installation

        go get github.com/smugmug/goawsroles/roles_files

### Contact Us

Please contact opensource@smugmug.com for information related to this package. 
Pull requests also welcome!
