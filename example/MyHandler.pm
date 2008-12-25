package My::Package;
use Lemonldap::NG::Handler::SharedConf;
@ISA = qw(Lemonldap::NG::Handler::SharedConf);

__PACKAGE__->init ( {
    https               => 0,
    # Uncomment this to activate status module
    # status            => 1,

    # CUSTOM FUNCTION : if you want to create customFunctions in rules, declare them here
    #customFunctions    => 'function1 function2',
} );
1;
