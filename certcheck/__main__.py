"""
Entrypoint for the certcheck package.
"""
import sys
import asyncio
import certcheck

if __name__ == '__main__':
    try:
        asyncio.run(certcheck.main())
    except KeyboardInterrupt:
        sys.exit()
