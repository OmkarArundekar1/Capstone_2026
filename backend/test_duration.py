from neo4j.time import Duration
from datetime import datetime, timezone
d = Duration(years=0, months=0, days=0, seconds=100, nanoseconds=500000000)
print('Duration object attributes:')
print(f'  Type: {type(d)}')
print(f"  Dir: {[attr for attr in dir(d) if not attr.startswith('_')]}")
print(f"  Has 'seconds': {hasattr(d, 'seconds')}")
print(f"  Has 'days': {hasattr(d, 'days')}")
print(f"  Has 'months': {hasattr(d, 'months')}")
print(f"  Has 'years': {hasattr(d, 'years')}")
if hasattr(d, 'seconds'):
    print(f'\nActual duration.seconds: {d.seconds}')
if hasattr(d, 'days'):
    print(f'Actual duration.days: {d.days}')
print('\n---')
print('Note: Neo4j Duration should have seconds, nanoseconds, days, months attributes')
print('Total seconds calculation needs to combine all components')