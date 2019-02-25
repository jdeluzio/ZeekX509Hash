@load base/files/hash
@load base/files/x509

## Add hashs to the x509 log, comment out the ones you don't want to add
event file_new(f: fa_file)
    {
    Files::add_analyzer(f, Files::ANALYZER_SHA256);
    }

redef record X509::Info += {
    ## Adds new fields to the x509 record
    sha1: string &log &optional;
    md5: string &log &optional;
    sha256: string &log &optional;
};

event file_state_remove(f: fa_file) &priority=10
    {
    if ( ! f$info?$x509 )
        return;
    if ( f$info?$sha1 )
        f$info$x509$sha1 = f$info$sha1;
    if ( f$info?$md5 )
        f$info$x509$md5 = f$info$md5;
    if ( f$info?$sha256 )
        f$info$x509$sha256 = f$info$sha256;
    }
