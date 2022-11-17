
# Functions for identifying problem set go here

def identify(filename):
    # do static, dynamic, symbolic stuff to identify which type of binary we are looking at
    properties = {}
    properties['type'] = "overflow"
    if properties['type'] == "overflow":
        properties['ret2win'] = True

    return properties
