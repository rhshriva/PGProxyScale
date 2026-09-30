#!/usr/bin/env python3
"""Live opt-in held cursor and role virtualization on a size-one transaction pool."""
import argparse
import uuid
import psycopg
from psycopg import sql
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--host', default='host.docker.internal');p.add_argument('--port',type=int,default=6466)
p.add_argument('--database',default='virtual_transaction');p.add_argument('--backend-port',type=int,default=55439);p.add_argument('--backend-password',default=None)
a=p.parse_args()
def connect(direct=False):
    return psycopg.connect(host=a.host,port=a.backend_port if direct else a.port,dbname='conformance' if direct else a.database,user='postgres',autocommit=True,sslmode='disable',connect_timeout=3,password=a.backend_password if direct else None)
def query(c,text):
    with c.cursor() as cur:
        cur.execute(text,prepare=False)
        return cur.fetchall() if cur.description else cur.statusmessage

def cursors():
    with connect() as first:
        query(first,'BEGIN');query(first,'DECLARE snapshot SCROLL CURSOR WITH HOLD FOR SELECT x::int FROM generate_series(1,5) x');query(first,'COMMIT')
        # A second simultaneous frontend can borrow the only physical backend while
        # both independent snapshots remain live.
        with connect() as second:
            query(second,'BEGIN');query(second,'DECLARE snapshot SCROLL CURSOR WITH HOLD FOR SELECT x::int FROM generate_series(101,103) x');query(second,'COMMIT')
            assert query(first,'FETCH FORWARD 2 FROM snapshot')==[(1,),(2,)]
            assert query(second,'FETCH NEXT FROM snapshot')==[(101,)]
            assert query(first,'FETCH BACKWARD 1 FROM snapshot')==[(1,)]
            assert query(first,'FETCH LAST FROM snapshot')==[(5,)]
            assert query(first,'FETCH PRIOR FROM snapshot')==[(4,)]
            assert query(first,'MOVE ABSOLUTE 0 FROM snapshot')=='MOVE 0'
            assert query(first,'FETCH ALL FROM snapshot')==[(1,),(2,),(3,),(4,),(5,)]
            assert query(first,'FETCH NEXT FROM snapshot')==[]
            assert query(first,'FETCH PRIOR FROM snapshot')==[(5,)]
            assert query(second,'CLOSE snapshot')=='CLOSE CURSOR'
            assert query(first,'CLOSE snapshot')=='CLOSE CURSOR'
            assert query(second,'SELECT 7')==[(7,)]

def differential_positions():
    with connect(True) as native, connect() as virtual:
        for c in [native,virtual]:
            query(c,'BEGIN');query(c,'DECLARE compared SCROLL CURSOR WITH HOLD FOR SELECT x::int FROM generate_series(1,5) x');query(c,'COMMIT')
        requests=['FETCH FORWARD 0','FETCH NEXT','FETCH FORWARD 0','MOVE FORWARD 0','FETCH NEXT','MOVE BACKWARD 0','FETCH PRIOR','FETCH ABSOLUTE -1','FETCH RELATIVE -2','MOVE ABSOLUTE 0','FETCH ALL','FETCH PRIOR','FETCH BACKWARD ALL','FETCH NEXT','FETCH FORWARD -2','MOVE RELATIVE 2','FETCH NEXT','MOVE ABSOLUTE 100','FETCH PRIOR']
        for operation in requests:
            statement=operation+' FROM compared'
            expected=query(native,statement);actual=query(virtual,statement)
            assert actual==expected,(statement,actual,expected)
        query(virtual,'CLOSE compared')

def transactional_simple_cursor():
    with connect(True) as native,connect() as virtual:
        outcomes=[]
        for c in [native,virtual]:
            query(c,'BEGIN');query(c,'DECLARE held_tx SCROLL CURSOR WITH HOLD FOR SELECT x::int FROM generate_series(1,5) x');query(c,'COMMIT')
            query(c,'BEGIN');rows=query(c,'FETCH FORWARD 2 FROM held_tx');query(c,'ROLLBACK')
            # Cursor positioning is nontransactional: rollback does not rewind it.
            rows+=query(c,'FETCH NEXT FROM held_tx')
            query(c,'BEGIN');query(c,'CLOSE held_tx');query(c,'ROLLBACK')
            try:query(c,'FETCH NEXT FROM held_tx')
            except psycopg.Error as error:state=error.sqlstate
            else:raise AssertionError('rollback resurrected a closed cursor')
            outcomes.append((rows,state))
        assert outcomes[0]==outcomes[1],outcomes

def exact_snapshot():
    name='pgproxy_snapshot_'+uuid.uuid4().hex
    with connect(True) as admin, connect() as c:
        query(admin,f'CREATE TABLE {name}(n int)');query(admin,f'INSERT INTO {name} VALUES(1),(2)')
        try:
            query(c,'BEGIN');query(c,f'DECLARE saved SCROLL CURSOR WITH HOLD FOR SELECT n FROM {name} ORDER BY n');query(c,'COMMIT')
            query(admin,f'UPDATE {name} SET n=n+100')
            assert query(c,'FETCH ALL FROM saved')==[(1,),(2,)]
            query(c,'CLOSE saved')
        finally:query(admin,f'DROP TABLE {name}')

def native_fallback():
    # Oversize and GUC-sensitive snapshots retain their real backend and pristine
    # position. They are still usable, and explicit CLOSE returns the pool slot.
    for select in ["SELECT x::text FROM generate_series(1,30000) x", "SELECT '2020-01-01'::date"]:
        with connect() as c:
            query(c,'BEGIN');query(c,'DECLARE native SCROLL CURSOR WITH HOLD FOR '+select);query(c,'COMMIT')
            rows=query(c,'FETCH NEXT FROM native');assert len(rows)==1
            query(c,'CLOSE native')
            with connect() as second:assert query(second,'SELECT 1')==[(1,)]

def extended_access():
    with connect() as c:
        query(c,'BEGIN');query(c,"DECLARE saved SCROLL CURSOR WITH HOLD FOR SELECT 1::int2, -2::int4, 9223372036854775807::int8, true::bool, 'hello'::text, '00112233-4455-6677-8899-aabbccddeeff'::uuid, NULL::int4");query(c,'COMMIT')
        with c.cursor(binary=True) as cur:
            cur.execute('FETCH ALL FROM saved',prepare=True)
            assert cur.fetchall()==[(1,-2,9223372036854775807,True,'hello',uuid.UUID('00112233-4455-6677-8899-aabbccddeeff'),None)]
            cur.execute('FETCH ALL FROM saved',prepare=True);assert cur.fetchall()==[]
        query(c,'MOVE ABSOLUTE 0 FROM saved')
        with c.cursor() as cur:
            cur.execute('FETCH NEXT FROM saved',prepare=True);assert len(cur.fetchall())==1
        c.execute('CLOSE saved',prepare=True)

def extended_portals(interleave=False):
    import os,socket,struct
    def compare(c):
        query(c,'BEGIN');query(c,'DECLARE chunked SCROLL CURSOR WITH HOLD FOR SELECT x::int FROM generate_series(1,5) x');query(c,'COMMIT')
        stream=socket.socket(fileno=os.dup(c.fileno()));stream.settimeout(3)
        def send(tag,payload):stream.sendall(tag+struct.pack('!I',len(payload)+4)+payload)
        def exact(n):
            value=b''
            while len(value)<n:
                part=stream.recv(n-len(value))
                if not part:raise AssertionError('protocol EOF')
                value+=part
            return value
        def drain(stops):
            messages=[]
            while True:
                tag=exact(1);n=struct.unpack('!I',exact(4))[0];payload=exact(n-4);messages.append((tag,payload))
                if tag in stops:return messages
        def execute(n):send(b'E',b'p\0'+struct.pack('!I',n));send(b'H',b'');return drain([b'C',b's',b'E'])
        send(b'P',b'st\0FETCH ALL FROM chunked\0\0\0');send(b'B',b'p\0st\0\0\0\0\0\0\x01\0\x01');send(b'D',b'Pp\0')
        chunks=[execute(2)]
        if interleave=='close':
            send(b'P',b'early_close\0CLOSE chunked\0\0\0');send(b'B',b'q\0early_close\0\0\0\0\0\0\0');send(b'E',b'q\0'+struct.pack('!I',0));send(b'H',b'');chunks.append(drain([b'C',b's',b'E']))
            send(b'D',b'Pp\0');send(b'H',b'');chunks.append(drain([b'T',b'n',b'E']))
        elif interleave:
            send(b'P',b'early_move\0MOVE ABSOLUTE 0 FROM chunked\0\0\0');send(b'B',b'q\0early_move\0\0\0\0\0\0\0');send(b'E',b'q\0'+struct.pack('!I',0));send(b'H',b'');chunks.append(drain([b'C',b's',b'E']))
            send(b'P',b'early_fetch\0FETCH NEXT FROM chunked\0\0\0');send(b'B',b'r\0early_fetch\0\0\0\0\0\0\0');send(b'E',b'r\0'+struct.pack('!I',0));send(b'H',b'');chunks.append(drain([b'C',b's',b'E']))
        chunks.extend([execute(2),execute(2),execute(2)])
        send(b'S',b'');chunks.append(drain([b'Z']))
        if interleave=='close':
            stream.close()
            return chunks
        # Sync invalidates the portal, while the prepared statement persists.
        send(b'B',b'p\0st\0\0\0\0\0\0\0');chunks.append(execute(0));send(b'S',b'');chunks.append(drain([b'Z']))
        # Closing a protocol statement gives CloseComplete; utility portal repeat
        # returns ERROR 55000 and skips the rest of the cycle until Sync.
        send(b'C',b'Sst\0');send(b'S',b'');chunks.append(drain([b'Z']))
        send(b'P',b'move\0MOVE ABSOLUTE 0 FROM chunked\0\0\0');send(b'B',b'p\0move\0\0\0\0\0\0\0');chunks.append(execute(0));chunks.append(execute(0));send(b'S',b'');chunks.append(drain([b'Z']))
        stream.close()
        # Native errors include source location fields. Compare stable SQLSTATE
        # and all remaining protocol tags/values, rather than server source paths.
        normalized=[]
        for chunk in chunks:
            normalized.append([(tag, next(field[1:] for field in payload.split(b'\0') if field.startswith(b'C')) if tag==b'E' else payload) for tag,payload in chunk])
        return normalized
    if interleave=='close':
        # The tested PostgreSQL fixture crashes in the native suspended CLOSE
        # path. Keep that probe out of normal acceptance runs; independently
        # verify the proxy owns its cached rows/metadata after cursor closure.
        with connect() as virtual:chunks=compare(virtual)
        values=[struct.unpack('!i',payload[6:])[0] for chunk in chunks for tag,payload in chunk if tag==b'D']
        assert values==[1,2,3,4,5],chunks
        initial=next(payload for tag,payload in chunks[0] if tag==b'T')
        assert chunks[2]==[(b'T',initial)],chunks
        assert chunks[-1]==[(b'Z',b'I')],chunks
    else:
        with connect(True) as native,connect() as virtual:
            expected=compare(native);actual=compare(virtual)
            assert actual==expected,(actual,expected)

def extended_interleaved_portals():
    extended_portals(True)

def extended_closed_cursor_portal():
    extended_portals('close')

def mixed_cycles_fail_closed():
    import os,socket,struct
    for virtual_first in [True,False]:
        with connect() as c:
            query(c,'BEGIN');query(c,'DECLARE mixed SCROLL CURSOR WITH HOLD FOR SELECT 9::int');query(c,'COMMIT')
            stream=socket.socket(fileno=os.dup(c.fileno()));stream.settimeout(3)
            def send(tag,payload):stream.sendall(tag+struct.pack('!I',len(payload)+4)+payload)
            def exact(n):
                out=b''
                while len(out)<n:
                    part=stream.recv(n-len(out))
                    if not part:raise AssertionError('EOF before typed rejection')
                    out+=part
                return out
            statements=[b'v\0FETCH ALL FROM mixed\0\0\0',b'r\0SELECT 123\0\0\0']
            if not virtual_first:statements.reverse()
            for statement in statements:send(b'P',statement)
            send(b'H',b'')
            tags=[]
            while True:
                tag=exact(1);n=struct.unpack('!I',exact(4))[0];payload=exact(n-4);tags.append(tag)
                if tag==b'E':
                    assert b'C0A000\0' in payload,payload
                    assert b'SFATAL\0' in payload,payload
                    break
            assert all(tag==b'1' for tag in tags[:-1]),tags
            assert stream.recv(1)==b'', 'rejected mixed cycle stayed open'
            stream.close()

def roles():
    suffix=uuid.uuid4().hex[:12];r1='pv_a_'+suffix;r2='pv_b_'+suffix;t='pv_table_'+suffix
    with connect(True) as admin:
        query(admin,f'CREATE ROLE {r1}');query(admin,f'CREATE ROLE {r2}')
        query(admin,f'CREATE TABLE {t}(tenant text)');query(admin,f"INSERT INTO {t} VALUES('{r1}'),('{r2}')")
        query(admin,f'GRANT SELECT ON {t} TO {r1},{r2}');query(admin,f'ALTER TABLE {t} ENABLE ROW LEVEL SECURITY');query(admin,f'CREATE POLICY tenant ON {t} USING (tenant=current_user::text)')
        try:
            with connect() as one,connect() as two:
                query(one,f'SET ROLE {r1}');query(two,f'SET ROLE {r2}')
                for c,role in [(one,r1),(two,r2),(one,r1)]:
                    assert query(c,f'SELECT tenant FROM {t}')==[(role,)]
                query(one,'RESET ALL');assert query(one,'SELECT current_user::text')==[(r1,)]
                query(one,'BEGIN');query(one,f'SET ROLE {r2}');query(one,'ROLLBACK');assert query(one,'SELECT current_user::text')==[(r1,)]
                query(one,'RESET ROLE');assert query(one,'SELECT current_user::text')==[('postgres',)]
        finally:
            query(admin,f'DROP TABLE {t}');query(admin,f'DROP ROLE {r1}');query(admin,f'DROP ROLE {r2}')

for case in [cursors,differential_positions,transactional_simple_cursor,exact_snapshot,native_fallback,extended_access,extended_portals,extended_interleaved_portals,extended_closed_cursor_portal,mixed_cycles_fail_closed,roles]:
    case();print('PASS '+case.__name__,flush=True)
