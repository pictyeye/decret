# pragma: no cover
import sys
from decret.decret import main
from decret.config import FatalError

try:
    main()
except FatalError as fatal_exc:
    print(fatal_exc, file=sys.stderr)
    sys.exit(1)
