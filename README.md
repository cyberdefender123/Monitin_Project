# Monitin Project

This mini anti-virus programme calculates the hash of a file and sends it to the website 'virustotal.com' via the REST API in order for it to be scanned by many anti-viruses.

A score is calculated to determine the risk that the file contains a virus. This is based on whether the file is executable or not, 
and by how many anti-viruses on virustotal.com deem it suspicious.
