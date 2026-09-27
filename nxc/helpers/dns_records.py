"""AD DNS binary record structures used by LDAP inventory."""


import socket
from struct import unpack

from impacket.structure import Structure


class DNS_RECORD(Structure):
    """
    dnsRecord - used in LDAP
    [MS-DNSP] section 2.3.2.2
    """

    structure = (
        ("DataLength", "<H-Data"),
        ("Type", "<H"),
        ("Version", "B=5"),
        ("Rank", "B"),
        ("Flags", "<H=0"),
        ("Serial", "<L"),
        ("TtlSeconds", ">L"),
        ("Reserved", "<L=0"),
        ("TimeStamp", "<L=0"),
        ("Data", ":"),
    )


class DNS_COUNT_NAME(Structure):
    """
    DNS_COUNT_NAME
    Used for FQDNs in LDAP communication
    MUST be converted to DNS_RPC_NAME for RPC communication
    [MS-DNSP] section 2.2.2.2.2
    """

    structure = (("Length", "B-RawName"), ("LabelCount", "B"), ("RawName", ":"))

    def toFqdn(self):
        ind = 0
        labels = []
        for _i in range(self["LabelCount"]):
            nextlen = unpack("B", self["RawName"][ind: ind + 1])[0]
            labels.append(self["RawName"][ind + 1: ind + 1 + nextlen].decode("utf-8"))
            ind += nextlen + 1
        # For the final dot
        labels.append("")
        return ".".join(labels)


class DNS_RPC_RECORD_A(Structure):
    """
    DNS_RPC_RECORD_A
    [MS-DNSP] section 2.2.2.2.4.1
    """

    structure = (("address", ":"),)

    def formatCanonical(self):
        return socket.inet_ntoa(self["address"])

    def fromCanonical(self, canonical):
        self["address"] = socket.inet_aton(canonical)


class DNS_RPC_RECORD_NODE_NAME(Structure):
    """
    DNS_RPC_RECORD_NODE_NAME
    [MS-DNSP] section 2.2.2.2.4.2
    """

    structure = (("nameNode", ":", DNS_COUNT_NAME),)


class DNS_RPC_RECORD_AAAA(Structure):
    """
    DNS_RPC_RECORD_AAAA
    [MS-DNSP] section 2.2.2.2.4.17
    """

    structure = (("ipv6Address", "16s"),)

    def formatCanonical(self):
        return socket.inet_ntop(socket.AF_INET6, self["ipv6Address"])
