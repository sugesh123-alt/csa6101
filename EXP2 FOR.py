import socket
from datetime import datetime
import ipaddress

# ---------------------------------------------------------
# DNS-BASED RECONNAISSANCE
# ---------------------------------------------------------

print("=" * 60)
print("        DNS RECONNAISSANCE TOOL")
print("=" * 60)

# Get domain from investigator
domain = input("Enter domain name: ").strip()

# Remove protocol if investigator enters it
domain = domain.replace("https://", "")
domain = domain.replace("http://", "")
domain = domain.split("/")[0]

# Record investigation time
investigation_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

print("\n" + "=" * 60)
print("INVESTIGATION DETAILS")
print("=" * 60)

print("Domain queried     :", domain)
print("Investigation time :", investigation_time)


# ---------------------------------------------------------
# Validate domain
# ---------------------------------------------------------

if not domain or "." not in domain:

    print("\nQuery Result       : INVALID DOMAIN")
    print("The entered value does not appear to be a valid domain.")

else:

    try:

        # -------------------------------------------------
        # DNS Resolution
        # -------------------------------------------------

        hostname, aliases, addresses = socket.gethostbyname_ex(domain)

        print("\nQuery Result       : SUCCESS")

        print("\nDNS Information")
        print("-" * 60)

        print("Canonical hostname :", hostname)

        if aliases:
            print("Aliases            :")
            for alias in aliases:
                print("  -", alias)
        else:
            print("Aliases            : None")

        print("\nResolved IP Addresses:")

        for address in addresses:
            print("  -", address)

        # -------------------------------------------------
        # Additional address information
        # -------------------------------------------------

        print("\nAddress Details")
        print("-" * 60)

        for address in addresses:

            try:
                ip = ipaddress.ip_address(address)

                if ip.version == 4:
                    print(address, "-> IPv4 address")
                else:
                    print(address, "-> IPv6 address")

            except ValueError:
                print(address, "-> Unknown address type")

    except socket.gaierror:

        print("\nQuery Result       : NO DNS RESULT")
        print("The domain could not be resolved.")
        print("It may not exist, may have no DNS record,")
        print("or DNS resolution may currently be unavailable.")

    except Exception as error:

        print("\nQuery Result       : ERROR")
        print("An unexpected error occurred:")
        print(error)


# ---------------------------------------------------------
# End of investigation
# ---------------------------------------------------------

print("\n" + "=" * 60)
print("Investigation completed.")
print("=" * 60)
