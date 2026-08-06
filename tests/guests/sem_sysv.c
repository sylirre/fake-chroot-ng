/* System V semaphores and message queues, the ordinary path (M22).
 *
 * Run once under chroot-ng and once straight under qemu-aarch64, where the same
 * code reaches the host kernel's real semget/semop/semctl and msgget/msgsnd/
 * msgrcv/msgctl. The two must agree byte for byte — the whole point of porting
 * this from arm64chroot rather than inventing it. (Unlike the shm differential,
 * which leans on qemu's own shmat, nothing here is emulated on the reference
 * side: every call is forwarded straight to the kernel.)
 *
 * Nothing prints an id, a pid or a time: those differ between the two runs by
 * construction. Only values, counts, lengths and errno names are compared.
 */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <unistd.h>
#include "sysvipc.h"

/* glibc hides MSG_EXCEPT behind __USE_GNU; the value is the same everywhere. */
#ifndef MSG_EXCEPT
#define MSG_EXCEPT 020000
#endif

static const char *e(void) {
    switch (errno) {
    case EACCES:  return "EACCES";
    case EAGAIN:  return "EAGAIN";
    case E2BIG:   return "E2BIG";
    case EEXIST:  return "EEXIST";
    case EFBIG:   return "EFBIG";
    case EIDRM:   return "EIDRM";
    case EINVAL:  return "EINVAL";
    case ENOENT:  return "ENOENT";
    case ENOMSG:  return "ENOMSG";
    case ERANGE:  return "ERANGE";
    default:      return strerror(errno);
    }
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    /* ---- semaphores ---- */
    int sid = semget(IPC_PRIVATE, 3, IPC_CREAT | 0600);
    printf("semget: %s\n", sid >= 0 ? "ok" : e());
    if (sid < 0)
        return 1;

    union cng_semun u;
    printf("fresh values: %d %d %d\n", semctl(sid, 0, GETVAL),
           semctl(sid, 1, GETVAL), semctl(sid, 2, GETVAL));

    u.val = 5;
    printf("setval(1,5): %d then %d\n", semctl(sid, 1, SETVAL, u),
           semctl(sid, 1, GETVAL));

    /* A multi-operation vector applies as a whole. */
    struct sembuf ops[2] = {{1, -2, 0}, {0, +3, 0}};
    printf("semop(-2,+3): %d -> %d %d\n", semop(sid, ops, 2),
           semctl(sid, 0, GETVAL), semctl(sid, 1, GETVAL));

    /* ...and rolls back entirely when one operation in it cannot proceed: the
     * +9 must NOT stick, because the -99 after it blocks. */
    struct sembuf mixed[2] = {{0, +9, 0}, {2, -99, IPC_NOWAIT}};
    int rc = semop(sid, mixed, 2);
    printf("atomic rollback: rc=%d %s -> %d\n", rc, rc < 0 ? e() : "-",
           semctl(sid, 0, GETVAL));

    unsigned short vals[3] = {7, 8, 9};
    u.array = vals;
    printf("setall: %d\n", semctl(sid, 0, SETALL, u));
    unsigned short got[3] = {0, 0, 0};
    u.array = got;
    printf("getall: %d [%u %u %u]\n", semctl(sid, 0, GETALL, u), got[0], got[1],
           got[2]);

    struct semid_ds ds;
    u.buf = &ds;
    printf("ipc_stat: %d nsems=%lu mode=%o\n", semctl(sid, 0, IPC_STAT, u),
           (unsigned long)ds.sem_nsems, ds.sem_perm.mode & 0777);
    ds.sem_perm.mode = 0640;
    printf("ipc_set: %d\n", semctl(sid, 0, IPC_SET, u));
    printf("mode now: %d %o\n", semctl(sid, 0, IPC_STAT, u),
           ds.sem_perm.mode & 0777);

    /* Nobody is sleeping on this set, so both counts are zero. */
    printf("ncnt/zcnt: %d %d\n", semctl(sid, 0, GETNCNT), semctl(sid, 0, GETZCNT));

    struct sembuf nb = {2, -1, IPC_NOWAIT};
    rc = semop(sid, &nb, 1);
    printf("nowait on 9: rc=%d\n", rc);
    unsigned short zero[3] = {0, 0, 0};
    u.array = zero;
    semctl(sid, 0, SETALL, u);
    rc = semop(sid, &nb, 1);
    printf("nowait on 0: rc=%d %s\n", rc, rc < 0 ? e() : "-");

    /* Error cases, in the kernel's own order of checking. */
    struct sembuf bad = {99, -1, 0};
    rc = semop(sid, &bad, 1);
    printf("bad sem_num: rc=%d %s\n", rc, rc < 0 ? e() : "-");
    rc = semop(sid, ops, 0);
    printf("zero nsops: rc=%d %s\n", rc, rc < 0 ? e() : "-");
    printf("bad semid getval: rc=%d %s\n", semctl(999999, 0, GETVAL),
           semctl(999999, 0, GETVAL) < 0 ? e() : "-");
    u.val = 99999;
    rc = semctl(sid, 0, SETVAL, u);
    printf("setval out of range: rc=%d %s\n", rc, rc < 0 ? e() : "-");

    /* Which of semctl's refusals wins, which is not one order but two.
     * ksys_semctl sends SETVAL straight into semctl_setval(), whose opening
     * statement is the value-range test — ahead of the id lookup, the semnum
     * bound and the permission check alike — and which then bounds semnum
     * BEFORE calling ipcperms(). semctl_main(), serving the read commands, does
     * the opposite: ipcperms() first and the semnum bound after. A single
     * shared order cannot produce both. */
    {
        int shut = semget(IPC_PRIVATE, 2, IPC_CREAT | 0000); /* no access */
        u.val = 99999;
        printf("setval range beats bad id: %s\n",
               semctl(999999, 0, SETVAL, u) < 0 ? e() : "-");
        printf("setval range beats bad semnum: %s\n",
               semctl(sid, 99, SETVAL, u) < 0 ? e() : "-");
        printf("setval range beats no access: %s\n",
               semctl(shut, 0, SETVAL, u) < 0 ? e() : "-");
        u.val = 1;
        printf("setval semnum beats access: %s\n",
               semctl(shut, 99, SETVAL, u) < 0 ? e() : "-");
        printf("getval access beats semnum: %s\n",
               semctl(shut, 99, GETVAL) < 0 ? e() : "-");
        printf("getncnt access beats semnum: %s\n",
               semctl(shut, 99, GETNCNT) < 0 ? e() : "-");
        printf("getval semnum when readable: %s\n",
               semctl(sid, 99, GETVAL) < 0 ? e() : "-");
        semctl(shut, 0, IPC_RMID);
    }
    printf("rmid: %d\n", semctl(sid, 0, IPC_RMID));
    printf("op after rmid: %d %s\n", semop(sid, ops, 1),
           semop(sid, ops, 1) < 0 ? e() : "-");

    /* Keyed lookup: create, find, IPC_EXCL, and a key that is not there. */
    key_t k = 0x63bb0001;
    int a = semget(k, 2, IPC_CREAT | 0600);
    int b = semget(k, 2, 0);
    printf("keyed: created=%d found-same=%d\n", a >= 0, a == b);
    rc = semget(k, 2, IPC_CREAT | IPC_EXCL | 0600);
    printf("keyed excl: rc=%d %s\n", rc, rc < 0 ? e() : "-");
    rc = semget(k, 5, 0);
    printf("keyed too small: rc=%d %s\n", rc, rc < 0 ? e() : "-");
    semctl(a, 0, IPC_RMID);
    rc = semget(k, 2, 0);
    printf("keyed after rmid: rc=%d %s\n", rc, rc < 0 ? e() : "-");

    /* ---- message queues ---- */
    int q = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
    printf("msgget: %s\n", q >= 0 ? "ok" : e());
    if (q < 0)
        return 1;

    struct {
        long mtype;
        char t[32];
    } m;
    for (long t = 1; t <= 3; t++) {
        m.mtype = t;
        snprintf(m.t, sizeof m.t, "body-%ld", t);
        printf("msgsnd(%ld): %d\n", t, (int)msgsnd(q, &m, sizeof m.t, 0));
    }
    struct msqid_ds mds;
    printf("qnum/cbytes: %d %lu %lu\n", msgctl(q, IPC_STAT, &mds),
           (unsigned long)mds.msg_qnum, (unsigned long)mds.msg_cbytes);

    /* msgtyp 2 takes that type; msgtyp -2 takes the lowest type <= 2; msgtyp 0
     * takes the head. Together these pin the whole selection rule. */
    memset(&m, 0, sizeof m);
    printf("rcv type 2: %d %ld %s\n", (int)msgrcv(q, &m, sizeof m.t, 2, 0),
           m.mtype, m.t);
    memset(&m, 0, sizeof m);
    printf("rcv type -3: %d %ld %s\n", (int)msgrcv(q, &m, sizeof m.t, -3, 0),
           m.mtype, m.t);
    memset(&m, 0, sizeof m);
    printf("rcv type 0: %d %ld %s\n", (int)msgrcv(q, &m, sizeof m.t, 0, 0),
           m.mtype, m.t);
    rc = (int)msgrcv(q, &m, sizeof m.t, 0, IPC_NOWAIT);
    printf("rcv empty: rc=%d %s\n", rc, rc < 0 ? e() : "-");

    /* MSG_EXCEPT takes anything BUT the named type. */
    m.mtype = 4;
    strcpy(m.t, "four");
    msgsnd(q, &m, sizeof m.t, 0);
    m.mtype = 5;
    strcpy(m.t, "five");
    msgsnd(q, &m, sizeof m.t, 0);
    memset(&m, 0, sizeof m);
    printf("rcv except 4: %d %ld %s\n",
           (int)msgrcv(q, &m, sizeof m.t, 4, MSG_EXCEPT), m.mtype, m.t);

    /* A buffer smaller than the message is E2BIG unless MSG_NOERROR, and the
     * message stays on the queue for the retry either way. */
    char small[4];
    struct {
        long mtype;
        char t[4];
    } sm;
    rc = (int)msgrcv(q, &sm, sizeof small, 0, 0);
    printf("rcv too small: rc=%d %s\n", rc, rc < 0 ? e() : "-");
    rc = (int)msgrcv(q, &sm, sizeof small, 0, MSG_NOERROR);
    printf("rcv truncated: rc=%d %ld\n", rc, sm.mtype);

    m.mtype = 0;
    rc = (int)msgsnd(q, &m, sizeof m.t, 0);
    printf("send type 0: rc=%d %s\n", rc, rc < 0 ? e() : "-");

    printf("qbytes default: %d %lu\n", msgctl(q, IPC_STAT, &mds),
           (unsigned long)mds.msg_qbytes);
    printf("rmid: %d\n", msgctl(q, IPC_RMID, NULL));
    rc = msgctl(q, IPC_STAT, &mds);
    printf("stat after rmid: rc=%d %s\n", rc, rc < 0 ? e() : "-");

    printf("done\n");
    return 0;
}
