# $Id: AuthenDBMFile.pm,v 1.5 2002/10/23 18:51:51 reggers Exp $

package Apache::AuthenDBMFile;

$Apache::AuthenDBMFile::VERSION = '0.01';

use Apache ();
use Apache::Constants qw(OK AUTH_REQUIRED DECLINED SERVER_ERROR);
use Carp;

use strict;

sub handler {
    my $r = shift;

    # Continue only if the first request.

    return OK 
	unless $r->is_initial_req;

    # Get the password, userid and password file

    my ($res,$pass,$user);
    ($res, $pass) = $r->get_basic_auth_pw;
    return $res if $res;
    return AUTH_REQUIRED
	unless $user=$r->connection->user;

    # Gotta have a password file that we can read.

    my($file, %hash);
    croak "No 'AuthenDBMFile' provided!"
	unless $file=$r->dir_config("AuthenDBMFile");
    croak "Cannot read '$file'!"
	unless dbmopen(%hash,$file,0600);

    # index into database for <password>:<group-list> entry

    $_=$hash{$user}; 	dbmclose(%hash);
    my($cipher,$groups)=split(/:/,$_);

    unless ($_ && (crypt($pass,$cipher) eq $cipher)) {
	$r->note_basic_auth_failure;
	return AUTH_REQUIRED;
    }

    return OK;
}

1;

__END__

=head1 NAME

Apache::AuthenDBMFile - Authentication with a "password" database

=head1 SYNOPSIS

 # Authentication in .htaccess/httpd.conf

 AuthName "User Authentication"
 AuthType Basic

 # authenticate using a password database

 PerlAuthenHandler Apache::AuthenDBMFile
 PerlSetVar AuthenDBMFile /some/file

 # constraints

 require valid-user
 # require user larry moe curly

=head1 DESCRIPTION

This Perl module allows authentication against a "password" database
-- each entry in the database is indexed by a B<userid> and consists
of a "B<cipher>:B<grouplist>" where the B<cipher> is a standard Unix
crypt of the user's password. The B<grouplist> is compatible with
B<AuthDBMGroupFile> constraints.

The B<AuthenDBMFile> parameter specifies the password database that
should be searched.

=head1 SEE ALSO

L<Apache>, L<mod_perl>, L<AuthenFile>

=head1 AUTHOR

Reg Quinton E<lt>reggers@ist.uwaterloo.caE<gt>, 18-Oct-2002.

=head1 COPYRIGHT

The Apache::AuthenDBMFile module is free software; you can redistribute
it and/or modify it under the same terms as Perl itself.

=cut
