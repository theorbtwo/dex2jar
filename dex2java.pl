#!/usr/bin/perl
use warnings;
use strict;
use lib '/mnt/shared/projects/wii/wii/lib';
use Binary;
use Data::Dump::Streamer;
use Scalar::Util 'looks_like_number';
$|=1;

# http://android.git.kernel.org/?p=platform/dalvik.git;a=blob_plain;f=docs/dex-format.html;hb=refs/heads/master

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
    Dump $class_def;

    print "$_ " for grep {$_ ne '_raw'} keys %{$class_def->{access_flags}};
    print binary_name_to_pretty($class_def->{class});
    print " : ", binary_name_to_pretty($class_def->{superclass}), "\n";
    if (@{$class_def->{interfaces}}) {
      print "  implements\n";
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

  if (m/^L(.*);/) {
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
                                       my ($std) = @_;


                                       my @array;
                                       my $eater = main->can("eat_".$context->{type});
                                       if (!$eater) {
                                         warn "Don't know how to eat a ".$context->{type};
                                         return;
                                       }
                                       for my $i (0..$context->{size}-1) {
                                         my $e = $eater->($std);
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
