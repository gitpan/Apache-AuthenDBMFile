# $Id: Makefile.PL,v 1.3 2002/10/25 16:25:45 reggers Exp $

use ExtUtils::MakeMaker;

WriteMakefile(
   NAME          => 'Apache::AuthenDBMFile',
   DISTNAME      => 'Apache-AuthenDBMFile',
   VERSION_FROM  => 'AuthenDBMFile.pm',
   'dist' => { COMPRESS=>"gzip", SUFFIX=>"gz" }
);
