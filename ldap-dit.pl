#! /usr/pkg/bin/perl

use strict ;
use warnings ;

use Tree::Simple ;	# apt install libtree-simple-perl

# https://metacpan.org/pod/Tree::Simple

# devel/p5-File-Find-Rule-Perl
# devel/p5-Test-Version
# devel/p5-Tree-Simple

my $annuaire = undef ;
my $apex = undef ;

while ( <> )
{
   if ( my ( $dn ) = /^dn: (.+)$/ )
   {
      if ( not defined ( $annuaire ) )
      {
         $annuaire->{$dn} = Tree::Simple->new ( $dn ) ;
         $apex = $dn ;
      }
      else
      {
         my ( $premier , $suite ) = $dn =~ /^([^,]+),(.+)$/ ;
         $annuaire->{$dn} = Tree::Simple->new ( $dn , $annuaire->{$suite} ) ;
      }
   }
}

my $profondeur = -1 ;
my @aff_vert = ( ) ;

print "$apex\n" ;

$annuaire->{$apex}->traverse
(
    sub
    {
       my ( $element ) = @_ ;
       my $tag = $element->getNodeValue ( ) ;
       $profondeur = $element->getDepth ( ) ;
       if ( $profondeur != 0 )
       {
          foreach my $p ( 0 .. $profondeur -  1 )
          {
             if ( $aff_vert[$p] )
             {
                print '|   ' ;
             }
             else
             {
                print '    ' ;
             }
          }
       }
       print '+-- ' . $tag . "($profondeur)" . "\n" ;

       if ( not $element->isLeaf ( ) )
       {
          $aff_vert[$profondeur] = 1 if $element->isFirstChild ( ) ;
          $aff_vert[$profondeur] = 0 if $element->isLastChild ( ) ;
       }
   }
) ;
