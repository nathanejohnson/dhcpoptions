# dhcpoptions

simple cli utility for encoding and decoding
some dhcp options.  for now, only 121 is supported.

usage:

    % dhcpoptions 121 -route-arg '192.168.0.0/16,192.168.1.1' -route-arg '10.0.0.0/8,192.168.1.1'
    option 121 val: 0x10c0a8c0a80101080ac0a80101
    % dhcpoptions 121 -encoded-arg 0x10c0a8c0a80101080ac0a80101
    net: 192.168.0.0/16 -> 192.168.1.1
    net: 10.0.0.0/8 -> 192.168.1.1
