
def hex_str(b):
    if not b:
        return ""
    return ":".join('%x' % c for c in b)