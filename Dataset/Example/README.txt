This directory contains example data for ten selected CVEs. Each CVE is organized in a separate subdirectory named after its corresponding CVE ID. The structure and content of each subdirectory are as follows:

patch.txt: Contains the patch information related to the CVE.

patch_list.txt: Lists all commit URLs associated with the vulnerable file(s) affected by the CVE.

commit/: Stores all commits related to the vulnerable file. Each file is named after its corresponding commit ID and contains the detailed code changes of that commit.

result/: Stores the intermediate and final outputs of the experiment.

a.c: The complete source code of the vulnerable file before modification.

b.c: The complete source code of the vulnerable file after modification.

Vul-Crit-Seq.txt: Contains the vulnerability-critical statement sequence extracted during the experiment.

Vul-Rel-St.txt: Contains the vulnerability-related statements extracted during the experiment.

<hash>.txt: Records the final experimental result—the vulnerability-introducing commit—named after the corresponding commit hash.
