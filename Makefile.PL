use ExtUtils::MakeMaker;


print "Checking for Net::NIS ........ ";
eval {
    require Net::NIS;
};
if ($@) {
    print "failed\n";
    print <<EOT;
$@
The Net::NIS module is required for this module to work properly.
You can obtain this module from CPAN as "NIS-a2".  It claims to be
an alpha release, but it looks like there's been no need to
update it since 10-Nov-95.
EOT
    exit;
} else {
    print " ok\n";
}



WriteMakefile(
    'NAME'	=> 'Apache::AuthenNIS',
    'VERSION_FROM' => 'AuthenNIS.pm', # finds $VERSION
    'dist' => {COMPRESS => 'gzip', SUFFIX => 'gz'}
);
