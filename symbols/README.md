
This directory contains .go and .json files with identifiers of clusters, commands and attributes.
These are generated using tools in gen directory.

As source data xml from following directory is used: https://github.com/project-chip/connectedhomeip/tree/master/data_model/clusters

To regenerate, run from the project root:

    ./symbols/generate.sh        # uses latest version (1.6)
    ./symbols/generate.sh 1.5   # pin to a specific Matter spec version
