#!/usr/bin/perl
use warnings;
use strict;
use lib '/mnt/shared/projects/wii/wii/lib';
use Binary;
use Data::Dump::Streamer;
use Scalar::Util 'looks_like_number';
use 5.10.0;
$|=1;

# http://source.android.com/tech/dalvik/dex-format.html

my $by_index = {};
my $by_offset = {};

my @access_flags = (
                    1 => 'public',
                    2 => 'private',
                    4 => 'protected',
                    8 => 'static',
                    0x10 => 'final',
                    0x20 => 'synchronized',
                    0x40 => 'volatile',
                    0x40 => 'bridge',
                    0x80 => 'transient',
                    0x80 => 'varargs',
                    0x100 => 'native',
                    0x200 => 'interface',
                    0x400 => 'abstract',
                    0x800 => 'strict',
                    0x1000 => 'synthetic',
                    0x2000 => 'annotation',
                    0x4000 => 'enum',
                    0x10000 => 'constructor',
                    0x20000 => 'declared_synchronized',
                   );

for my $infn (@ARGV) {
  open my $infh, "<", $infn or die "Can't open $infn: $!";

  my $head = Binary::eat_desc([$infh, undef, ""],
                              [
                               magic => sub {
                                 Binary::eat_required(shift, 'a8', "dex\n035\0");
                               },
                               checksum => \&uint,
                               signature => 'a20',
                               file_size => \&uint,
                               header_size => sub {
                                 Binary::eat_required(shift, \&uint, 0x70);
                               },
                               endian_tag => sub {
                                 Binary::eat_required(shift, \&uint, 0x12345678);
                               },
                               link_size => \&uint,
                               link_off => \&uint,
                               map_off => \&uint,
                               string_ids_size => \&uint,
                               string_ids_off => \&uint,
                               type_ids_size => \&uint,
                               type_ids_off => \&uint,
                               proto_ids_size => \&uint,
                               proto_ids_off => \&uint,
                               field_ids_size => \&uint,
                               field_ids_off => \&uint,
                               method_ids_size => \&uint,
                               method_ids_off => \&uint,
                               class_defs_size => \&uint,
                               class_defs_off => \&uint,
                               data_size => \&uint,
                               data_off => \&uint,
                              ]);
  print Dump $head;

  my $map = Binary::eat_at([$infh, undef, ""],
                           $head->{map_off},
                           sub {
                             Binary::eat_counted(shift, \&uint, \&eat_map_item);
                           }
                          );
  #print Dump $map;

  #print Dump $by_index;

  for my $class_def (@{$by_index->{class_def_item}}) {
    local $class_def->{_context} = 'hidden';
    #Dump $class_def;

    print "// GENERATED OUTPUT\n";

    print join(" ", grep {$_ ne '_raw'} keys %{$class_def->{access_flags}});
    print " class ";
    print binary_name_to_pretty($class_def->{class});
    print "\n  extends ", binary_name_to_pretty($class_def->{superclass}), "\n";
    if (@{$class_def->{interfaces}}) {
      print "\n  implements\n";
      print "   ", binary_name_to_pretty($_), "\n" for @{$class_def->{interfaces}};
    }
    print "{\n";

    my @static_values = @{$class_def->{static_values}};
    for my $field (map {@$_}
                   $class_def->{class_data}{static_fields},
                   #$class_def->{class_data}{instance_fields}
                  ) {
      my $flags = join " ", grep {$_ ne '_raw'} keys %{$field->{access_flags}};
      my $type = binary_name_to_pretty($field->{field}{type});
      my $name = $field->{field}{name};
      

      if ($field->{access_flags}{static} and @static_values) {
        my $val = shift @static_values;
        # FIXME: This will fail when there is a static string that happens to consist of all digits?
        if (!looks_like_number $val) {
          $val = quotemeta($val);
          $val = qq<"$val">;
        }
        print "  $flags $type $name = $val;\n";
      } else {
        print "  $flags $type $name;\n";
      }
    }


    for my $method (map {@$_}
                    $class_def->{class_data}{direct_methods},
                    $class_def->{class_data}{virtual_methods}
                   ) {
      my $flags = $method->{access_flags};
      my $flags_str = join " ", grep {!$_ ~~ ['_raw', 'constructor']} keys %$flags;

      my $ret = binary_name_to_pretty($method->{method}{proto}{return_type});
      my $name = $method->{method}{name};
      
      $flags_str .= " " if $flags_str;
      print "  $flags_str$ret $name (\n";
      for my $i (0..@{$method->{method}{proto}{parameters}}-1) {
        my $name = $method->{code}{debug_info}{parameter_names}[$i] // "argument_$i";
        my $type = binary_name_to_pretty($method->{method}{proto}{parameters}[$i]);
        
        print "    $type $name,\n";
      }
      print "  ) {\n";

      my @insns = @{$method->{code}{insns}};
      my @debug_entries = @{$method->{code}{debug_info}{entries}};
      my $orig_len = @insns;
      my $current_debug;
      
      while (@insns) {
        my $address = $orig_len - @insns;

        print "loc_$address:\n";

        while (@debug_entries and $debug_entries[0]{address} <= $address) {
          $current_debug = shift @debug_entries;

          print "// $current_debug->{source_file} line $current_debug->{line}\n";
          print "// prologue ends here\n" if $current_debug->{prologue_end};
          print "// epilogue begins here\n" if $current_debug->{epilogue_begin};
        }

        my $opcode = shift @insns;

        # http://android.git.kernel.org/?p=platform/dalvik.git;a=blob_plain;f=docs/dalvik-bytecode.html;hb=refs/heads/master

        state $all_op_info = {
                              0x0a => ['11x', 'move-result'],
                              0x0c => ['11x', 'move-result-object'],
                              0x0d => ['11x', 'move-exception'],
                              0x0e => ['10x', 'return-void'],

                              0x12 => ['11n', 'const/4 vA, #+B'],
                              0x1a => ['21c', 'const-string'],

                              0x21 => ['12x', 'array-length'],
                              0x22 => ['21c', 'new-instance'],
                              0x23 => ['22c', 'new-array'],

                              0x28 => ['10t', 'goto'],
                              0x29 => ['20t', 'goto'],

                              0x32 => ['22t', 'if-eq'],
                              0x33 => ['22t', 'if-ne'],
                              0x34 => ['22t', 'if-lt'],
                              0x35 => ['22t', 'if-ge'],
                              0x36 => ['22t', 'if-gt'],
                              0x37 => ['22t', 'if-le'],

                              0x38 => ['21t', 'if-eqz'],
                              0x39 => ['21t', 'if-nez'],
                              0x3a => ['21t', 'if-ltz'],
                              0x3b => ['21t', 'if-gez'],
                              0x3c => ['21t', 'if-gtz'],
                              0x3d => ['21t', 'if-lez'],

                              0x44 => ['23x', 'aget'],
                              0x45 => ['23x', 'aget-wide'],
                              0x46 => ['23x', 'aget-object'],
                              0x47 => ['23x', 'aget-boolean'],
                              0x48 => ['23x', 'aget-byte'],
                              0x49 => ['23x', 'aget-char'],
                              0x4a => ['23x', 'aget-short'],
                              0x4b => ['23x', 'aput'],
                              0x4c => ['23x', 'aput-wide'],
                              0x4d => ['23x', 'aput-object'],
                              0x4e => ['23x', 'aput-boolean'],
                              0x4f => ['23x', 'aget-byte'],
                              0x50 => ['23x', 'aget-char'],
                              0x51 => ['23x', 'aget-short'],

                              0x52 => ['22c', 'iget'],
                              0x53 => ['22c', 'iget-wide'],
                              0x54 => ['22c', 'iget-object'],
                              0x55 => ['22c', 'iget-boolean'],
                              0x56 => ['22c', 'iget-byte'],
                              0x57 => ['22c', 'iget-char'],
                              0x58 => ['22c', 'iget-short'],
                              0x59 => ['22c', 'iput'],
                              0x5a => ['22c', 'iput-wide'],
                              0x5b => ['22c', 'iput-object'],
                              0x5c => ['22c', 'iput-boolean'],
                              0x5d => ['22c', 'iput-byte'],
                              0x5e => ['22c', 'iput-char'],
                              0x5f => ['22c', 'iput-short'],


                              0x60 => ['21c', 'sget'],
                              0x61 => ['21c', 'sget-wide'],
                              0x62 => ['21c', 'sget-object'],
                              0x63 => ['21c', 'sget-boolean'],
                              0x64 => ['21c', 'sget-byte'],
                              0x65 => ['21c', 'sget-char'],
                              0x66 => ['21c', 'sget-short'],
                              0x67 => ['21c', 'sput'],
                              0x68 => ['21c', 'sput-wide'],
                              0x69 => ['21c', 'sput-object'],
                              0x6a => ['21c', 'sput-boolean'],
                              0x6b => ['21c', 'sput-byte'],
                              0x6c => ['21c', 'sput-char'],
                              0x6d => ['21c', 'sput-short'],

                              0x6e => ['35c', 'invoke-virtual'],
                              0x6f => ['35c', 'invoke-super'],
                              0x70 => ['35c', 'invoke-direct'],
                              0x71 => ['35c', 'invoke-static'],
                              0x72 => ['35c', 'invoke-interface'],

                              0xd8 => ['22b', 'add-int'],
                              0xd9 => ['22b', 'rsub-int'],
                              0xda => ['22b', 'mul-int'],
                              0xdb => ['22b', 'div-int'],
                              0xdc => ['22b', 'rem-int'],
                              0xdd => ['22b', 'and-int'],
                              0xde => ['22b', 'or-int'],
                              0xdf => ['22b', 'xor-int'],
                              0xe0 => ['22b', 'shl-int'],
                              0xe1 => ['22b', 'shr-int'],
                              0xe2 => ['22b', 'ushr-int'],
                             };

        my $op_info = $all_op_info->{$opcode & 0xFF};
        if (!$op_info) {
          die sprintf "Unknown opcode 0x%02x", $opcode & 0xFF;
        }

        my $data;


        # http://android.git.kernel.org/?p=platform/dalvik.git;a=blob_plain;f=docs/instruction-formats.html;hb=refs/heads/master
        given ($op_info->[0]) {
          when ('10t') {
            # AA|op -- op +AA
            $data->{a} = 'loc_'.($address + unpack 'c', pack 'C', $opcode>>8);
          }

          when ('10x') {
            # nop.
          }

          when ('11n') {
            # B|A|op -- op vA, #+B
            $data->{a} = 'v'.(($opcode >> 8)&0xF);
            $data->{b} = $opcode >> 12;
          }

          when ('11x') {
            $data->{a} = 'v'.($opcode >> 8);
          }

          when ('12x') {
            # B|A|op -- op vA, vB
            $data->{a} = 'v'.(($opcode >> 8)&0xF);
            $data->{b} = 'v'.($opcode >> 12);
          }

          when ('20t') {
            # ØØ|op AAAA -- op +AAAA
            $data->{a} = 'loc_'.($address+unpack 's', pack 'S', shift(@insns));
          }
          when ('21c') {
            # AA|op BBBB -- op vAA, xxxx@BBBB
            $data->{a} = 'v'.($opcode >> 8);
            $data->{b} = shift @insns;
          }
          when('21t') {
            # AA|op BBBB -- op vAA, +BBBB
            $data->{a} = 'v'.($opcode >> 8);
            $data->{b} = 'loc_'.($address+unpack 's', pack 'S', shift(@insns));
          }
          when ('22b') {
            # AA|op CC|BB -- op vAA, vBB, #+CC
            $data->{a} = 'v'.($opcode >> 8);
            my $next = shift @insns;
            $data->{c} = $next >> 8;
            $data->{b} = 'v'.($next & 0xFF);
          }
          when ('22c') {
            # B|A|op CCCC-- op vA, vB, kind@CCCC
            $data->{b} = 'v'.($opcode >> 12);
            $data->{a} = 'v'.(($opcode >> 8) & 0xF);
            $data->{c} = shift @insns;
          }
          when ('22t') {
            # B|A|op CCCC - op vA, vB, +CCCC
            $data->{b} = 'v'.($opcode >> 12);
            $data->{a} = 'v'.(($opcode >> 8) & 0xF);
            $data->{c} = 'loc_'.($address+(unpack 's', pack 'S', shift(@insns)));
          }
          when ('23x') {
            # AA|op CC|BB - op vAA, vBB, vCC
            $data->{a} = 'v'.($opcode >> 8);
            my $next = shift @insns;
            $data->{c} = 'v'.($next >> 8);
            $data->{b} = 'v'.($next & 0xFF);
          }
          when ('35c') {
            # B|A|op CCCC G|F|E|D -- op {vD, vE, vF, vG, vA}, kind@CCCC
            $data->{b} = ($opcode >> (8+4));
            $data->{a} = 'v'.(($opcode >> 8) & 0xF);
            $data->{c} = shift @insns;
            my $gfed = shift @insns;
            $data->{g} = 'v'.(($gfed >> 12) & 0xF);
            $data->{f} = 'v'.(($gfed >>  8) & 0xF);
            $data->{e} = 'v'.(($gfed >>  4) & 0xF);
            $data->{d} = 'v'.(($gfed >>  0) & 0xF);
          }
          default {
            die "Unknown opcode format $_";
          }
        }


        my ($a, $b, $c) = @{$data}{qw<a b c>};
        given ($op_info->[1]) {
          when ('iget-object') {
            my $field = $by_index->{field_id_item}[$c]->{name};
            print "   $a = $b.$field; // object field\n";
          }
          when ('iput-object') {
            my $field = $by_index->{field_id_item}[$c]->{name};
            print "   $b.$field = $a; // object field\n";
          }
          when ('add-int') {
            print "    $a = $b + $c;\n";
          }
          when ('array-length') {
            my $dest = $data->{a};
            my $array = $data->{b};
            print "    $dest = $array.length;\n";
          }
          when ('aput-object') {
            my $src = $data->{a};
            my $array = $data->{b};
            my $i = $data->{c};

            print "    $array\[$i] = $src;\n";
          }
          when ('aget-object') {
            my $dest = $data->{a};
            my $array = $data->{b};
            my $i = $data->{c};

            print "    $dest = $array\[$i];\n";
          }
          when ('goto') {
            my $dest = $data->{a};
            print "    goto $dest;\n";
          }
          when ('if-eq') {
            my ($a) = $data->{a};
            my ($b) = $data->{b};
            my $dest = $data->{c};
            print "    if ($a == $b) goto $dest;\n";
          }
          when ('if-ne') {
            my ($a) = $data->{a};
            my ($b) = $data->{b};
            my $dest = $data->{c};
            print "    if ($a != $b) goto $dest;\n";
          }
          when ('if-ge') {
            my ($a) = $data->{a};
            my ($b) = $data->{b};
            my $dest = $data->{c};
            print "    if ($a >= $b) goto $dest;\n";
          }
          when ('if-eqz') {
            my $reg = $data->{a};
            my $targ = $data->{b};
            
            # FIXME: Java has no goto statement!
            print "    if ($reg == 0) goto $targ;\n";
          }
          when (['move-result', 'move-result-object']) {
            my $reg = $data->{a};
            print "   $reg = ret;\n";
          }
          when ('move-exception') {
            print "   $a = caught;\n";
          }
          when ('const/4 vA, #+B') {
            my $reg = $data->{a};
            my $val = $data->{b};
            print "    $reg = $val;\n";
          }
          when('const-string') {
            my $reg = $data->{a};
            my $val = quotemeta($by_index->{string_id_item}[$data->{b}]);
            
            print "    $reg = \"$val\";\n";
          }
          when ('return-void') {
            print "    return;\n";
          }
          when ('sput-object') {
            my $field = $by_index->{field_id_item}[$data->{b}];
            my $field_name = $field->{name};
            my $reg = $data->{a};

            print "    this.$field_name = $reg;\n";
          }
          when ('sget-object') {
            my $field = $by_index->{field_id_item}[$data->{b}];
            my $field_name = $field->{name};
            my $reg = $data->{a};

            print "    $reg = this.$field_name;\n";
          }
          when ('invoke-direct') {
            my $meth = $by_index->{method_id_item}[$data->{c}];
            my $meth_name = $meth->{name};

            if ($meth_name eq '<init>') {
              # is a constructor
              $meth_name = "$a = new ".binary_name_to_pretty($meth->{class});
            } else {
              die;
            }

            # This is decidedly confusing...
            my @args = (@{$data}{qw<d e f g a>})[2..$data->{b}];

            print "    $meth_name(", join(", ", @args), ");\n";
          }
          when (['invoke-interface', 'invoke-virtual', 'invoke-static']) {
            my $meth = $by_index->{method_id_item}[$data->{c}];
            my $meth_name = $meth->{name};
            my $object = $data->{d};
            my $arg_count = $data->{b}-1;

            my @args = (@{$data}{qw<e f g>})[0..$arg_count-1];
            my $args = join ", ", @args;

            my $opname = $op_info->[1];
            print "   ret = $object.$meth_name($args); // $opname\n";
          }
          when ('new-instance') {
            my $reg = $data->{a};
            my $type = binary_name_to_pretty($by_index->{type_id_item}[$data->{b}]);

            print "    // new-instance $type in $reg\n";
          }
          when ('new-array') {
            my $ret = $data->{a};
            my $size = $data->{b};
            my $type = binary_name_to_pretty($by_index->{type_id_item}[$data->{c}]);
            # The name of an array type ends in '[]'.  Take them off
            # so we can add on a *filled* pair of []s.
            $type =~ s/\[\]$//;

            print "    $ret = new $type\[$size\]();\n";
          }
          default {
            Dump $data;
            die "Unknown opcode $_";
          }
        }
      }

      print "  }\n\n";
    }
    
    print "}\n";
    print "\n\n\n";
  }

  $by_index = {};
}

sub binary_name_to_pretty {
  local ($_) = @_;

  my %cores = (
               Z => 'boolean',
               B => 'byte',
               C => 'char',
               D => 'double',
               F => 'float',
               I => 'int',
               J => 'long',
               S => 'short',
               V => 'void',
              );

  if (exists $cores{$_}) {
    return $cores{$_};
  }

  if (s/^\[//) {
    return binary_name_to_pretty($_).'[]';
  } elsif (m/^L(.*);/) {
    my $inner = $1;
    $inner =~ s!/!.!g;
    return "$inner";
  } else {
    die "binary_name_to_pretty_name($_)";
  }
}

sub eat_map_item {
  Binary::eat_desc(shift,
                   [
                    type => sub {
                      Binary::eat_enum(shift, \&ushort,
                                       {
                                        0 => 'header_item',
                                        1 => 'string_id_item',
                                        2 => 'type_id_item',
                                        3 => 'proto_id_item',
                                        4 => 'field_id_item',
                                        5 => 'method_id_item',
                                        6 => 'class_def_item',
                                        0x1000 => 'map_list',
                                        0x1001 => 'type_list',
                                        0x1002 => 'annotation_set_ref_list',
                                        0x1003 => 'annotation_set_item',
                                        0x2000 => 'class_data_item',
                                        0x2001 => 'code_item',
                                        0x2002 => 'string_data_item',
                                        0x2003 => 'debug_info_item',
                                        0x2004 => 'annotation_item',
                                        0x2005 => 'encoded_array_item',
                                        0x2006 => 'annotations_directory_item',
                                       });
                    },
                    unused => \&ushort,
                    size => \&uint,
                    offset => \&uint,
                    thing => sub {
                      my ($fh, $context) = @{$_[0]};
                      Binary::eat_at(shift,
                                     $context->{offset},
                                     sub {
                                       my ($conv) = @_;
                                       my ($fh, $context, $address) = @$conv;

                                       my @array;
                                       my $eater = main->can("eat_".$context->{type});
                                       if (!$eater) {
                                         warn "Don't know how to eat a ".$context->{type};
                                         return;
                                       }
                                       for my $i (0..$context->{size}-1) {
                                         my $e = $eater->([$fh, $context, $address.'.'.$i]);
                                         if (ref $e eq 'HASH') {
                                           delete $e->{_context};
                                         }

                                         $by_index->{$context->{type}}[$i] = $e;

                                         $array[$i] = $e;
                                       }
                                       
                                       #print Dump \@array;
                                       return \@array;
                                     }
                                    );
                    }
                   ]);
}

sub eat_header_item {
  # We've already parsed the header to get here!
  return undef;
}

sub eat_string_id_item {
  my $s = Binary::eat_at(shift, \&uint,
                         [
                          # Number of utf16 code-points after decoding.
                          size => \&uleb128,
                          # FIXME: actually mutf8
                          data => sub {
                            Binary::eat_terminated_string(shift, 'utf8', "\0");
                          }
                         ]);
  return $s->{data};
}

sub eat_type_id_item {
  # Index of a string in the string_id_item table.
  my $i = uint(@_);
  $by_index->{string_id_item}[$i];
}

sub eat_proto_id_item {
  Binary::eat_desc(shift,
                   [
                    # index into the string_ids
                    shorty => sub {
                      $by_index->{string_id_item}[uint(shift)]
                    },
                    # index into the type_ids
                    return_type => sub {
                      $by_index->{type_id_item}[uint(shift)]
                    },
                    # offset for a type_list (or 0 if no parameters).
                    parameters => sub {
                      my $loc = uint($_[0]);
                      return [] if !$loc;
                      Binary::eat_at(shift, $loc, \&eat_type_list);
                    },
                   ]);
}

sub eat_type_list {
  Binary::eat_pad_until($_[0], 4, 0);
  Binary::eat_counted($_[0], \&uint,
                      sub {
                        $by_index->{type_id_item}[ushort(shift)];
                      });
}

sub eat_field_id_item {
  Binary::eat_desc(shift,
                   [
                    class => sub {
                      $by_index->{type_id_item}[ushort(shift)]
                    },
                    type => sub {
                      $by_index->{type_id_item}[ushort(shift)]
                    },
                    name => sub {
                      $by_index->{string_id_item}[uint(shift)]
                    }
                   ]);
}

sub eat_method_id_item {
  Binary::eat_desc(shift,
                   [
                    class => sub {
                      $by_index->{type_id_item}[ushort(shift)],
                    },
                    proto => sub {
                      $by_index->{proto_id_item}[ushort(shift)],
                    },
                    name => sub {
                      $by_index->{string_id_item}[uint(shift)],
                    },
                   ]);
}

sub eat_class_def_item {
  Binary::eat_desc(shift,
                   [
                    class => sub {
                      $by_index->{type_id_item}[uint(shift)]
                    },
                    access_flags => sub {
                      Binary::eat_bitmask(shift,
                                          \&uint,
                                          @access_flags);
                    },
                    superclass => sub {
                      $by_index->{type_id_item}[uint(shift)]
                    },
                    interfaces => sub {
                      my $loc = uint($_[0]);
                      return [] if !$loc;
                      Binary::eat_at(shift, $loc, \&eat_type_list);
                    },
                    source_file_idx => sub {
                      $by_index->{string_id_item}[uint(shift)]
                    },
                    annotations_off => \&uint,
                    class_data => sub {
                      my $loc = uint($_[0]);
                      return [] if !$loc;
                      Binary::eat_at(shift, $loc, \&eat_class_data_item);
                    },
                    static_values => sub {
                      my $loc = uint($_[0]);
                      return [] if !$loc;
                      Binary::eat_at(shift, $loc, \&eat_encoded_array_item);
                    },
                   ]
                  );
}

sub eat_encoded_array_item {
  &eat_encoded_array
}

sub eat_encoded_array {
  Binary::eat_counted(shift,
                      \&uleb128,
                      \&eat_encoded_value);
}

sub eat_encoded_value {
  my $arg_and_type = ubyte($_[0]);
  my $type = $arg_and_type & 0x1F;
  my $arg = $arg_and_type >> 5;
  my $len = $arg+1;

  if ($type == 0x17 and $len == 1) {
    return $by_index->{string_id_item}[ubyte($_[0])];
  } elsif ($type == 0x17 and $len == 2) {
    return $by_index->{string_id_item}[ushort($_[0])];
  } elsif ($type == 0x04 and $len == 4) {
    return uint($_[0]);
  } else {
    die "Don't know what to do with eat_encoded_value type=$type, arg=$arg";
  }
}

sub eat_class_data_item {
  Binary::eat_desc(shift,
                   [
                    static_fields_size => \&uleb128,
                    instance_fields_size => \&uleb128,
                    direct_methods_size => \&uleb128,
                    virtual_methods_size => \&uleb128,
                    static_fields => sub {
                      eat_encoded_field_list($_[0], $_[0][1]{static_fields_size});
                    },
                    instance_fields => sub {
                      eat_encoded_field_list($_[0], $_[0][1]{instance_fields_size});
                    },
                    direct_methods => sub {
                      eat_encoded_method_list($_[0], $_[0][1]{direct_methods_size});
                    },
                    virtual_methods => sub {
                      eat_encoded_method_list($_[0], $_[0][1]{virtual_methods_size});
                    },
                   ]
                  );
}

sub eat_encoded_field_list {
  my ($context, $length) = @_;

  my @a;
  my $prev_idx = 0;
  for my $i (0..$length-1) {
    my $e = eat_encoded_field($_[0]);
    push @a, $e;
    $prev_idx += $e->{field_idx_diff};
    $e->{field_idx} = $prev_idx;
    $e->{field} = $by_index->{field_id_item}[$prev_idx];
  }

  return \@a;
}

sub eat_encoded_field {
  Binary::eat_desc(shift,
                   [
                    field_idx_diff => \&uleb128,
                    access_flags => sub {Binary::eat_bitmask(shift, \&uleb128, @access_flags)}
                   ]);
}

sub eat_encoded_method_list {
  my ($context, $length) = @_;

  my @a;
  my $prev_idx = 0;
  for my $i (0..$length-1) {
    my $e = eat_encoded_method($_[0]);
    push @a, $e;
    $prev_idx += $e->{method_idx_diff};
    $e->{method_idx} = $prev_idx;
    $e->{method} = $by_index->{method_id_item}[$prev_idx];
  }

  return \@a;
}

sub eat_encoded_method {
  Binary::eat_desc(shift,
                   [
                    method_idx_diff => \&uleb128,
                    access_flags => sub {Binary::eat_bitmask(shift, \&uleb128, @access_flags)},
                    code => sub {
                      Binary::eat_at(shift,
                                     \&uleb128,
                                     \&eat_code_item);
                    }
                   ]);
}

sub eat_annotation_set_item {
  Binary::eat_counted(shift,
                      \&uint,
                      [
                       annotation_off => \&uint
                      ]);
}

my $first_only_thing;
sub eat_code_item {
  #return if $first_only_thing++ > 0;

  Binary::eat_desc(shift,
                   [
                    initial_padding => sub {
                      Binary::eat_pad_until(shift, 4, 0);
                    },

                    registers_size => \&ushort,
                    # words of incoming arguments.
                    ins_size => \&ushort,
                    # words of outing arguments ?
                    outs_size => \&ushort,
                    # in *items*
                    tries_size => \&ushort,
                    debug_info => sub {
                      Binary::eat_at(shift, \&uint, \&eat_debug_info_item);
                    },

                    insns => sub {
                      Binary::eat_counted(shift, \&uint, \&ushort);
                    },
                    padding => sub {
                      my ($fh, $context) = @{$_[0]};

                      if ($context->{tries_size} > 0 and
                          (0+@{$context->{insns}}) & 1) {
                        return Binary::eat_desc(shift, 'v');
                      } else {
                        return undef;
                      }
                    },

                    tries => sub {
                      my ($fh, $context) = @{$_[0]};
                      Binary::eat_counted(shift,
                                          $context->{tries_size},
                                          [
                                           start_addr => \&uint,
                                           insn_count => \&ushort,
                                           handler_off => \&ushort
                                          ]);
                    },

                    handlers => sub {
                      my ($fh, $context) = @{$_[0]};
                      #local $Binary::DEBUG=1;

                      return unless $context->{tries_size};

                      Binary::eat_counted(shift,
                                          \&uleb128,
                                          \&eat_encoded_catch_handler
                                         );
                    },
                   ]);
}

sub eat_debug_info_item {
  my $head = Binary::eat_desc($_[0],
                              [
                               line_start => \&uleb128,
                               parameter_names => sub {
                                 Binary::eat_counted(shift,
                                                     \&uleb128,
                                                     sub {
                                                       my $index = uleb128p1(shift);
                                                       if ($index == -1) {
                                                         return undef;
                                                       }
                                                       return $by_index->{string_id_item}[$index];
                                                     });
                               }
                              ]);

  my $address = 0;
  my $line = $head->{line_start};
  my $source_file = 'fixme_context';
  my $prologue_end;
  my $epilogue_begin;
  my @registers;
  my @dead_registers;

  my @entries;

  while (my $bytecode = ubyte($_[0])) {
    if ($bytecode == 1) {
      # DBG_ADVANCE_PC
      $address += uleb128($_[0]);
    } elsif ($bytecode == 2) {
      # DBG_ADVANCE_LINE
      $line += uleb128($_[0]);
    } elsif ($bytecode == 3) {
      # DBG_START_LOCAL
      my $register_num = uleb128($_[0]);
      my $name = $by_index->{string_id_item}[uleb128p1($_[0])];
      my $type = $by_index->{type_id_item}[uleb128p1($_[0])];

      $registers[$register_num] = {name => $name, type => $type};
    } elsif ($bytecode == 4) {
      # DBG_START_LOCAL_EXTENDED
      my $register_num = uleb128($_[0]);
      my $name = $by_index->{string_id_item}[uleb128p1($_[0])];
      my $type = $by_index->{type_id_item}[uleb128p1($_[0])];
      my $sig = $by_index->{string_id_item}[uleb128p1($_[0])];

      $registers[$register_num] = {name => $name, type => $type, sig => $sig};
      
    } elsif ($bytecode == 5) {
      # DBG_END_LOCAL
      my $register_num = uleb128($_[0]);

      $dead_registers[$register_num] = $registers[$register_num];
      $registers[$register_num] = undef;

    } elsif ($bytecode == 6) {
      # DBG_RESTART_LOCAL
      # docs seem to say that this is a new local with the same name & type as the old one
      my $register_num = uleb128($_[0]);
      
      $registers[$register_num] = $dead_registers[$register_num];
      $dead_registers[$register_num] = undef;

    } elsif ($bytecode == 7) {
      # DBG_SET_PROLOGUE_END
      $prologue_end=1;

    } elsif ($bytecode == 8) {
      # DBG_SET_EPILOGUE_BEGIN
      $epilogue_begin=1;

    } elsif ($bytecode == 9) {
      # DBG_SET_FILE
      my $index = uleb128p1($_[0]);
      if ($index == -1) {
        $source_file = '(unavailable)';
      } else {
        $source_file = $by_index->{string_id_item}[$index];
      }

    } elsif ($bytecode >= 0x0a) {
      # "special" opcodes
      my $adjusted_opcode = $bytecode-0x0a;
      $line += ($adjusted_opcode % 15) - 4;
      $address += int($adjusted_opcode / 15);
      
      # Copy!
      my $registers = [@registers];

      push @entries, {address => $address, line => $line, source_file => $source_file, prologue_end => $prologue_end, epilogue_begin => $epilogue_begin, registers => $registers};
      
      $prologue_end = 0;
      $epilogue_begin = 0;

    } else {
      Dump \@entries;
      die "FIXME: Unhandled debug state machine opcode $bytecode";
    }
  }

  $head->{entries} = \@entries;
  return $head;
}

sub eat_encoded_catch_handler {
  my ($fh, $context) = @{$_[0]};
  
  Binary::eat_desc(shift,
                   [
                    size => \&sleb128,
                    handlers => sub {
                      Binary::eat_counted($_[0],
                                          abs($_[0][1]{size}),
                                          \&eat_encoded_type_addr_pair
                                         );
                    },
                    catch_all_handler => sub {
                      if ($_[0][1]{size} < 1) {
                        return eat_encoded_type_addr_pair($_[0]);
                      } else {
                        return undef;
                      }
                    }
                   ]);
}

sub eat_encoded_type_addr_pair {
  Binary::eat_desc(shift,
                   [
                    type => sub {$by_index->{type_id_item}[uleb128(shift)]},
                    addr => \&uleb128
                   ]);
}

sub ubyte {
  Binary::eat_desc(shift, 'C');
}

sub ushort {
  Binary::eat_desc(shift, 'v');
}

sub uint {
  Binary::eat_desc(shift, 'V');
}

sub leb128_core {
  my ($fh, $context, $address) = @{$_[0]};

  my $v;
  my $len=0;
  while (1) {
    my $thisbyte = Binary::eat_desc([$_[0][0], $_[0][1], $_[0][2].".leb128"], 'C');

    $v |= ($thisbyte & 0x7f) << ($len*7);
    $len++;

    if (($thisbyte & 0x80) == 0) {
      # Terminator
      return ($v, $len);
    }
  }
}

sub uleb128 {
  my ($v, $len) = leb128_core(shift);
  return $v;
}

sub uleb128p1 {
  uleb128(shift)-1;
}

sub sleb128 {
  my ($v, $len) = leb128_core(shift);
  my $high_order_bit = !!($v & 1<<($len*7-1))+0;
  #my $v_without_hob = $v & ((1<<($len*7-1))-1);
  
  #printf("value=%032b\n", $v);
  #printf("value without hob=%d\n", $v_without_hob);
  #printf("len=$len\n");
  #printf("high-order bit=$high_order_bit\n");
  if ($high_order_bit) {
    $v |= 1<<$_ for $len*7 .. 31;

    #printf("value=%032b (after extension)\n", $v);

    $v = unpack('l', pack('L', $v));
    #printf("value=%d\n", $v);
  }

  return $v;
}
