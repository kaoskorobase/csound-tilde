/* +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
   file:        csound~.c
   authors:     orm finnendahl <finnendahl@folkwang-hochschule.de>
                stefan kersten <steve@k-hornz.de>
   content:     csound object for pd (linux)
   license:     public domain
                ( c ) 2002 finnendahl, kersten
   +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
   $Id: csound~.c,v 1.1 2002/02/18 22:58:31 steve Exp steve $
   +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */

#include "m_pd.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define CSD_VERSION             "0.1"

#define CSD_TMP_DIR             "/tmp/"
#define CSD_BIN_FILENAME        "/usr/local/bin/csound"
#define CSD_FLOAT_FMT           "%.6f"

#define CSD_MAX_NUM_CHANNELS    32
#define CSD_MAX_FIFO_NAME_LEN   64
#define CSD_MAX_CMD_LINE_LEN    256
#define CSD_MAX_ARGC            64

#define CSD_DO_PERF(x)          (((x)->x_pid >= 0) && !(x)->x_paused)

#ifdef DEBUG
#  define CSD_DEBUG_CALL(stmnt) stmnt
#else
#  define CSD_DEBUG_CALL(stmnt) /* NOP */
#endif /* DEBUG */
        
#if !defined(__GNUC__) || defined(DEBUG)
#  define __inline__            /* NOP */
#endif


/* +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
   + csound~ class
   +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */

static t_class *csound_tilde_class;


/* +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
   + csound~ object type
   +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */

typedef struct
{
    t_object    x_obj;                                          /* super */
    
    t_canvas    *x_canvas;                                      /* canvas */
    t_sample    x_f;                                            /* default signal inlet slot */

    char        x_evt_out_filename[CSD_MAX_FIFO_NAME_LEN];      /* line event fifo */
    int         x_evt_out_fd;

    char        x_snd_out_filename[CSD_MAX_FIFO_NAME_LEN];      /* pd-to-csound sound fifo */
    int         x_snd_out_fd;

    char        x_snd_in_filename[CSD_MAX_FIFO_NAME_LEN];       /* csound-to-pd sound fifo */
    int         x_snd_in_fd;

    t_symbol    *x_csound_bin_filename;                         /* csound executable */
    t_symbol    *x_csound_orc_filename;                         /* csound orchestra */
    t_symbol    *x_csound_sco_filename;                         /* csound score */

    pid_t       x_pid;                                          /* csound process pid */
    int         x_paused;                                       /* csound paused? */

    int         x_nchannels;                                    /* number of I/O channels (inlets/outlets) */
    int         x_outputflag;                                   /* sound output to csound? */

    t_sample    *x_buf;                                         /* contiguous buffer for pipe I/O */
    int         x_buf_byte_count;                               /* I/O buffer size in bytes */

    t_sample    *x_invec[CSD_MAX_NUM_CHANNELS];                 /* dsp performance input vector */
    t_sample    *x_outvec[CSD_MAX_NUM_CHANNELS];                /* dsp performance output vector */
    int         x_vec_frame_count;                              /* dsp performance buffer frame count */
} t_csound_tilde;


/* +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
   + helper functions
   +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */

static int 
csound_tilde_make_fifo(char *fname, int len)
{
    char *tmp_name;

    tmp_name = tempnam(CSD_TMP_DIR, "%s.%d");

    if (tmp_name == NULL) {
        error("csound~: tempnam(3) failed: %s", strerror(errno));
        return -1;
    }

    if (snprintf(fname, len, tmp_name, "csound~.fifo", getpid()) < 0) {
        error("csound~: buffer overflow while creating temporary file name");
        return -1;
    }

    CSD_DEBUG_CALL(post("DEBUG csound~ (make_fifo): creating fifo %s", fname));

    if (mkfifo(fname, 0666) < 0) {
        error("csound~: mkfifo(3) failed: %s", strerror(errno));
        return -1;
    }

    return 0;
}

__inline__ static void 
csound_tilde_send_event(t_csound_tilde *x, const char *method, t_symbol *s, int ac, t_atom *av)
{
    int         len;
    int         buf_len = MAXPDSTRING;
    char        buf[buf_len];
    char        *buf_pointer = buf;
    int         err;

    if (!CSD_DO_PERF(x)) {
        return;
    }

    if (s != NULL) {
        if ((len = snprintf(buf_pointer, buf_len, "%s ", s->s_name)) < 0)
            goto buffer_overflow_error;
        buf_pointer += len;
    }

    while (ac--) {
        switch(av->a_type) {
        case A_FLOAT:
            len = snprintf(buf_pointer, (buf + buf_len - buf_pointer), 
                           CSD_FLOAT_FMT " ", atom_getfloat(av));
            break;
        case A_SYMBOL:
            len = snprintf(buf_pointer, (buf + buf_len - buf_pointer), 
                           "%s ", atom_getsymbol(av)->s_name);
            break;
        default:
            bug("csound~ (%s): unknown argument type (ignored)", method);
            len = 0;
        }

        if (len < 0) {
            goto buffer_overflow_error;
        }

        av++; buf_pointer += len;
    }

    if ((len = snprintf(buf_pointer, buf + buf_len - buf_pointer, "\n")) < 0) {
        goto buffer_overflow_error;
    }

    err = write(x->x_evt_out_fd, buf, (buf_pointer + len - buf));

#ifdef DEBUG
    if (err < 0)
    {
        if (errno == EAGAIN) {
            post("DEBUG csound~ (%s): event output fifo overflow", method);
        } else {
            post("DEBUG csound~ (%s): event output fifo error: %s", method, strerror(errno));
        }
    }
#endif /* DEBUG */

    return;

 buffer_overflow_error:
    error("csound~ (%s): argument buffer overflow", method);
}

static void
csound_tilde_free_buffers(t_csound_tilde *x)
{
    CSD_DEBUG_CALL(post("DEBUG csound~: csound_tilde_free_buffers"));

    if (x->x_buf != NULL) {
        freebytes(x->x_buf, x->x_buf_byte_count);
        x->x_buf = NULL;
    }
}


/* +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
   + instance methods
   +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */

static void csound_tilde_close(t_csound_tilde *);

typedef struct
{
    char        *x_argv[CSD_MAX_ARGC+1];
    int         x_argc;
    char        x_buf[CSD_MAX_CMD_LINE_LEN];
    char        *x_bufp;
} t_csound_tilde_argv;

__inline__ static void
csound_tilde_argv_start(t_csound_tilde_argv *argv)
{
    argv->x_argc = 0;
    argv->x_bufp = argv->x_buf;
}

__inline__ static int
csound_tilde_argv_write(t_csound_tilde_argv *argv, const char *fmt, ...)
{
    int         len;
    va_list     ap;

    va_start(ap, fmt);    
    len = vsnprintf(argv->x_bufp, argv->x_buf + CSD_MAX_CMD_LINE_LEN - argv->x_bufp, fmt, ap);
    va_end(ap);

    if ((len < 0) || (argv->x_argc >= CSD_MAX_ARGC)) {
        return -1;
    }

    argv->x_argv[argv->x_argc++] = argv->x_bufp; argv->x_bufp += len+1;

    return 0;
}

__inline__ static int
csound_tilde_argv_write_filename(t_csound_tilde_argv *argv, t_canvas *canvas, char *filename)
{
    canvas_makefilename(canvas, filename, argv->x_bufp, 
                        argv->x_buf + CSD_MAX_CMD_LINE_LEN - argv->x_bufp);
    argv->x_argv[argv->x_argc++] = argv->x_bufp; argv->x_bufp += strlen(argv->x_bufp)+1;
    return 0;
}

__inline__ static char **
csound_tilde_argv_end(t_csound_tilde_argv *argv)
{
    argv->x_argv[argv->x_argc] = NULL;
    return argv->x_argv;
}

static void
csound_tilde_csound(t_csound_tilde *x, t_symbol *s, int ac, t_atom *av)
{
    char                *bin_filename;
    int                 pid;
    t_csound_tilde_argv argv;
    int                 err;
    char                **exec_argv;

    if (x->x_csound_orc_filename == NULL) {
        error("csound~ (csound): missing orchestra filename");
        return;
    }

    if (x->x_csound_orc_filename == NULL) {
        error("csound~ (csound): missing score filename");
        return;
    }

    /* free any resources */
    csound_tilde_close(x);

    /* create fifos */
    if (csound_tilde_make_fifo(x->x_evt_out_filename, CSD_MAX_FIFO_NAME_LEN) < 0) {
        error("csound~ (csound): couldn't create event output fifo");
        return;
    }

    if (x->x_outputflag) {
        if (csound_tilde_make_fifo(x->x_snd_out_filename, CSD_MAX_FIFO_NAME_LEN) < 0) {
            error("csound~ (csound): while creating sound out fifo: %s", strerror(errno));
            return;
        }
    }

    if (csound_tilde_make_fifo(x->x_snd_in_filename, CSD_MAX_FIFO_NAME_LEN) < 0) {
        error("csound~ (csound): couldn't create sound input fifo");
        return;
    }

    csound_tilde_argv_start(&argv);

    /* write executable filename */
    if (x->x_csound_bin_filename == NULL) {
        bin_filename = CSD_BIN_FILENAME;
    } else {
        bin_filename = x->x_csound_bin_filename->s_name;
    }

    if (csound_tilde_argv_write_filename(&argv, x->x_canvas, bin_filename) < 0) {
        goto buffer_overflow_error;
    }

    /* write user args */
    while (ac--) {
        switch(av->a_type) {
        case A_FLOAT:
            err = csound_tilde_argv_write(&argv, "%d", (int)atom_getfloat(av));
            av++; break;
        case A_SYMBOL:
            err = csound_tilde_argv_write(&argv, "%s", atom_getsymbol(av)->s_name);
            av++; break;
        default:
            post("csound~ (csound): unknown argument type (ignored)");
            av++; continue;
        }

        if (err < 0) {
            goto buffer_overflow_error;
        }
    }

    /* write internal args */

    /* float format, no header */
    if (csound_tilde_argv_write(&argv, "-fh") < 0) {
        goto buffer_overflow_error;
    }

    /* block size; here we should really use the correct dsp block size of
       the (sub-)patch we're in. */
    if (csound_tilde_argv_write(&argv, "-b%d", sys_getblksize()) < 0) {
        goto buffer_overflow_error;
    }

    if (csound_tilde_argv_write(&argv, "-B%d", sys_getblksize()) < 0) {
        goto buffer_overflow_error;
    }

    /* line events */
    if (csound_tilde_argv_write(&argv, "-L%s", x->x_evt_out_filename) < 0) {
        goto buffer_overflow_error;
    }

    /* sound I/O */
    if (x->x_outputflag) {
        if (csound_tilde_argv_write(&argv, "-i%s", x->x_snd_out_filename) < 0) {
            goto buffer_overflow_error;
        }
    }

    if (csound_tilde_argv_write(&argv, "-o%s", x->x_snd_in_filename) < 0) {
        goto buffer_overflow_error;
    }

    /* write orc and sco filenames */
    csound_tilde_argv_write_filename(&argv, x->x_canvas, x->x_csound_orc_filename->s_name);
    csound_tilde_argv_write_filename(&argv, x->x_canvas, x->x_csound_sco_filename->s_name);

    /* terminate arguments */
    exec_argv = csound_tilde_argv_end(&argv);

    /* fork csound process */
    if ((pid = fork()) < 0) {
        error("csound~ (csound): fork(2) failed");
        return;
    } 

    if (pid == 0) {
        /* child process */
#ifdef DEBUG
        {
            int i;
            for (i = 0; i < argv.x_argc; i++) {
                post("DEBUG csound~ (csound): argv[%d] = %s", i, argv.x_argv[i]);
            }
        }
#endif
        if (execv(bin_filename, exec_argv) < 0) {
            error("csound~ (csound): execv(3) failed: %s", strerror(errno));
            _exit (EXIT_FAILURE);
        }
    } else {
        /* parent process */
        x->x_pid         = pid;  /* store child pid */
        x->x_paused      = 1;    /* set flag to inhibit immediate communication */

        /* open event out fifo
           
           HACK-ALERT: on linux, opening O_RDWR will not cause open to fail,
           even if the other end of the pipe hasn't been opened for reading
           yet. */
        if ((x->x_evt_out_fd = open(x->x_evt_out_filename, (O_RDWR|O_NONBLOCK))) < 0) {
            error("csound~ (csound): couldn't open event output fifo: %s", strerror(errno));
            csound_tilde_close(x);
            return;
        }

        /* open sound out fifo */
        if (x->x_outputflag) {
            if ((x->x_snd_out_fd = open(x->x_snd_out_filename, (O_RDWR|O_NONBLOCK))) < 0) {
                error("csound~ (csound): couldn't open sound output fifo: %s", strerror(errno));
                csound_tilde_close(x);
                return;
            }
        }

        /* open sound in fifo */
        if ((x->x_snd_in_fd = open(x->x_snd_in_filename, (O_RDONLY|O_NONBLOCK))) < 0) {
            error("csound~ (csound): couldn't open sound input fifo: %s", strerror(errno));
            csound_tilde_close(x);
            return;
        }
    }

    return;

 buffer_overflow_error:
    error("csound~ (csound): argument buffer overflow");
}

static void
csound_tilde_close(t_csound_tilde *x)
{
    CSD_DEBUG_CALL(post("DEBUG csound~: csound_tilde_close"));

    /* terminate the csound process and wait for its exit */
    if (x->x_pid >= 0)
    {
        if (kill(x->x_pid, SIGQUIT) < 0) {
            CSD_DEBUG_CALL(post("DEBUG csound~ (close): kill(2) failed: %s", strerror(errno)));
        } else {
            waitpid(x->x_pid, NULL, 0);
        }
        x->x_pid = -1;
        x->x_paused = 1;
    }

    /* close any open file descriptors and remove temporary files */
    if (x->x_evt_out_fd >= 0) {
	if (close(x->x_evt_out_fd) < 0) {
	    CSD_DEBUG_CALL(post("DEBUG csound~: closing event output fifo failed: %s", strerror(errno)));
	}
        x->x_evt_out_fd = -1;
    }
    
    if (*x->x_evt_out_filename != '\0') {
        if (unlink(x->x_evt_out_filename) < 0) {
            CSD_DEBUG_CALL(post("DEBUG csound~: removing event output fifo failed: %s", strerror(errno)));
        }
        *x->x_evt_out_filename = '\0';
    }

    if (x->x_snd_out_fd >= 0) {
        if (close(x->x_snd_out_fd) < 0) {
            CSD_DEBUG_CALL(post("DEBUG csound~: closing sound output fifo failed: %s", strerror(errno)));
        }
        x->x_snd_out_fd = -1;
    }

    if (*x->x_snd_out_filename != '\0') {
        if (unlink(x->x_snd_out_filename) < 0) {
            CSD_DEBUG_CALL(post("DEBUG csound~: removing sound output fifo failed: %s", strerror(errno)));
        }
        *x->x_snd_out_filename = '\0';
    }

    if (x->x_snd_in_fd >= 0) {
	if (close(x->x_snd_in_fd) < 0) {
	    CSD_DEBUG_CALL(post("DEBUG csound~: closing sound input fifo failed: %s", strerror(errno)));
	}
        x->x_snd_in_fd = -1;
    }

    if (x->x_snd_in_filename != '\0') {
        if (unlink(x->x_snd_in_filename) < 0) {
            CSD_DEBUG_CALL(post("DEBUG csound~: removing sound input fifo failed: %s", strerror(errno)));
        }
        *x->x_snd_in_filename = '\0';
    }
}

static void
csound_tilde_bang(t_csound_tilde *x)
{
    CSD_DEBUG_CALL(post("DEBUG csound~: unpaused"));
    x->x_paused = 0;
}

static void
csound_tilde_pause(t_csound_tilde *x, t_symbol *s)
{
    CSD_DEBUG_CALL(post("DEBUG csound~: paused"));
    x->x_paused = 1;
}

static void
csound_tilde_list(t_csound_tilde *x, t_symbol *s, int ac, t_atom *av)
{
    csound_tilde_send_event(x, "list", NULL, ac, av);
}

static void
csound_tilde_anything(t_csound_tilde *x, t_symbol *s, int ac, t_atom *av)
{
    csound_tilde_send_event(x, "anything", s, ac, av);
}

static void
csound_tilde_bin(t_csound_tilde *x, t_symbol *s)
{
    x->x_csound_bin_filename = s;
}

static void
csound_tilde_orc(t_csound_tilde *x, t_symbol *s)
{
    x->x_csound_orc_filename = s;
}

static void
csound_tilde_sco(t_csound_tilde *x, t_symbol *s)
{
    x->x_csound_sco_filename = s;
}

static void
csound_tilde_status(t_csound_tilde *x)
{
    char *bin_filename  = CSD_BIN_FILENAME;
    char *orc_filename  = "not set";
    char *sco_filename  = "not set";

    if (x->x_csound_bin_filename != NULL) {
        bin_filename = x->x_csound_bin_filename->s_name;
    }

    if (x->x_csound_orc_filename != NULL) {
        orc_filename = x->x_csound_orc_filename->s_name;
    }

    if (x->x_csound_sco_filename != NULL) {
        sco_filename = x->x_csound_sco_filename->s_name;
    }

    {
        post("                                          ");
        post("+ csound~ status +++++++++++++++++++++++++");
    }

    if (x->x_pid < 0) {
        post("pid:              no process              ");
    } else {
        post("pid:              %d                      ", x->x_pid);
        post("evt out fifo:     %s                      ", x->x_evt_out_filename);
        post("evt out fd:       %d                      ", x->x_evt_out_fd);
        post("snd out fifo:     %s                      ", x->x_snd_out_filename);
        post("snd out fd:       %d                      ", x->x_snd_out_fd);
        post("snd in fifo:      %s                      ", x->x_snd_in_filename);
        post("snd in fd:        %d                      ", x->x_snd_in_fd);
    }
    {
        post("bin filename:     %s                      ", bin_filename);
        post("orc filename:     %s                      ", orc_filename);
        post("sco filename:     %s                      ", sco_filename);
        post("paused:           %d                      ", x->x_paused);
#ifdef DEBUG
        post("nchannels:        %d                      ", x->x_nchannels);
        post("buf size:         %d                      ", x->x_buf_byte_count);
#endif
        post("++++++++++++++++++++++++++++++++++++++++++");
        post("                                          ");
    }
}

static void
csound_tilde_help(t_csound_tilde *x)
{
    post("                                                                              ");
    post("+++ csound~ help +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
    post("                                                                              ");
    post("+++ instance creation ++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
    post("(nchnls oflag)        -- create a csound~ object with nchnls signal outlets   ");
    post("                         if oflag is nonzero create nchnls signal inlets      ");
    post("                         (orchestra should use same number of channels)       ");
    post("                                                                              ");
    post("+++ performance control ++++++++++++++++++++++++++++++++++++++++++++++++++++++");
    post("csound (list)         -- start csound performance with arguments              ");
    post("                         performance is initially paused                      ");
    post("close                 -- stop csound performance                              ");
    post("bang                  -- unpause csound performance                           ");
    post("pause                 -- pause csound performance                             ");
    post("                                                                              ");
    post("+++ realtime events ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
    post("list                                                                          ");
    post("anything              -- send a csound realtime score event                   ");
    post("                                                                              ");
    post("+++ object state +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
    post("bin (symbol)          -- set csound executable filename                       ");
    post("orc (symbol)          -- set orchestra filename                               ");
    post("sco (symbol)          -- set score filename                                   ");
    post("                                                                              ");
    post("+++ object information +++++++++++++++++++++++++++++++++++++++++++++++++++++++");
    post("status                -- display status report                                ");
    post("help                  -- display this help                                    ");
    post("                                                                              ");
    post("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
    post("                                                                              ");
}


/* +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
   + dsp performance routines
   +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */

__inline__ static int
csound_tilde_write_to_csound(t_csound_tilde *x, char *buf, int size)
{
    if (write(x->x_snd_out_fd, (void *)buf, size) < 0) {
#ifdef DEBUG
        if (errno == EAGAIN) {
            post("DEBUG csound~: sound output fifo overrun");
        } else {
            post("DEBUG csound~: sound output fifo error: %s", strerror(errno));
        }
#endif /* DEBUG */
        return -1;
    }
    return 0;
}

__inline__ static int
csound_tilde_read_from_csound(t_csound_tilde *x, char *buf, int size)
{
    int bytes_read;
    int bytes_missing;
    int res = 0;

    if ((bytes_read = read(x->x_snd_in_fd, (void *)buf, size)) < 0) {
#ifdef DEBUG
        if (errno == EAGAIN) {
            post("DEBUG csound~: sound input fifo underrun");
        } else {
            post("DEBUG csound~: sound input fifo error: %s", strerror(errno));
        }
#endif /* DEBUG */
        bytes_read = 0;
        res = -1;
    }

    /* zero out the part of the buffer we failed to read from csound.
       another possibility would be to repeat part of the signal. */
    if ((bytes_missing = size - bytes_read) > 0) {
        memset(((char *)buf)+bytes_read, 0, bytes_missing);
    }

    return res;
}

static t_int*
csound_tilde_perf_1(t_int *w)
{
    t_csound_tilde      *x              = (t_csound_tilde *)(w[1]);
    t_sample            *in             = x->x_invec[0];
    t_sample            *out            = x->x_outvec[0];
    int                 buf_byte_count  = x->x_buf_byte_count;

    if (CSD_DO_PERF(x)) {
        /* write to csound */
        if (x->x_outputflag) {
            csound_tilde_write_to_csound(x, (char *)in, buf_byte_count);
        }
        /* read from csound */
        csound_tilde_read_from_csound(x, (char *)out, buf_byte_count);
    } else {
        memset(out, 0, buf_byte_count);
    }

    return (w+2);
}

static t_int*
csound_tilde_perf_1_copy(t_int *w)
{
    t_csound_tilde      *x              = (t_csound_tilde *)(w[1]);

    int                 frame_count     = x->x_vec_frame_count;
    t_sample            *in             = x->x_invec[0];
    t_sample            *out            = x->x_outvec[0];

    int                 buf_byte_count  = x->x_buf_byte_count;
    t_sample            *buf            = x->x_buf;
    t_sample            *bufp           = buf;

    int                 n;

    if (CSD_DO_PERF(x)) {
        /* write to csound */
        if (x->x_outputflag) {
            n = frame_count;
            while (n--) {
                *(bufp++) = *(in++);
            }
            csound_tilde_write_to_csound(x, (char *)buf, buf_byte_count);
        }

        /* read from csound */
        csound_tilde_read_from_csound(x, (char *)buf, buf_byte_count);

        n = frame_count;
        while (n--) {
            *(out++) = *(buf++);
        }
    } else {
        while (frame_count--) {
            *(out++) = 0.0f;
        }
    }

    return (w+2);
}

static t_int*
csound_tilde_perf_2(t_int *w)
{
    t_csound_tilde      *x              = (t_csound_tilde *)(w[1]);

    int                 frame_count     = x->x_vec_frame_count;
    t_sample            *in1            = x->x_invec[0];
    t_sample            *in2            = x->x_invec[1];
    t_sample            *out1           = x->x_outvec[0];
    t_sample            *out2           = x->x_outvec[1];

    int                 buf_byte_count = x->x_buf_byte_count;
    t_sample            *buf            = x->x_buf;
    t_sample            *bufp           = buf;

    int                 n;

    if (CSD_DO_PERF(x)) {
        /* write to csound */
        if (x->x_outputflag) {
            n = frame_count;
            while (n--) {
                *(bufp++) = *(in1++);
                *(bufp++) = *(in2++);
            }
            csound_tilde_write_to_csound(x, (char *)buf, buf_byte_count);
        }

        /* read from csound */
        csound_tilde_read_from_csound(x, (char *)buf, buf_byte_count);

        n = frame_count;
        while (n--) {
            *(out1++) = *(buf++);
            *(out2++) = *(buf++);
        }
    } else {
        while (frame_count--) {
            *(out1++) = *(out2++) = 0.0f;
        }
    }

    return (w+2);
}

static t_int*
csound_tilde_perf_many(t_int *w)
{
    t_csound_tilde      *x              = (t_csound_tilde *)(w[1]);

    int                 nchannels       = x->x_nchannels;

    int                 frame_count     = x->x_vec_frame_count;
    t_sample            **invec         = x->x_invec;
    t_sample            *in;
    t_sample            **outvec        = x->x_outvec;
    t_sample            *out;

    int                 buf_byte_count  = x->x_buf_byte_count;
    t_sample            *buf            = x->x_buf;
    t_sample            *bufp;

    int                 chn;
    int                 n;

    if (CSD_DO_PERF(x)) {
        /* write to csound */
        if (x->x_outputflag) {
            for (chn = 0; chn < nchannels; chn++) {
                n       = frame_count;
                in      = invec[chn];
                bufp    = (buf+chn);

                while (n--) {
                    *bufp = *(in++);
                    bufp += nchannels;
                }
            }
            csound_tilde_write_to_csound(x, (char *)buf, buf_byte_count);
        }

        /* read from csound */
        csound_tilde_read_from_csound(x, (char *)buf, buf_byte_count);

        for (chn = 0; chn < nchannels; chn++) {
            n      = frame_count;
            bufp   = buf+chn;
            out    = outvec[chn];

            while (n--) {
                *(out++) = *bufp;
                bufp += nchannels;
            }
        }
    } else {
        for (chn = 0; chn < nchannels; chn++) {
            n   = frame_count;
            out = invec[chn];

            while (n--) {
                *(out++) = 0.0f;
            }
        }
    }

    return (w+2);
}

static void
csound_tilde_dsp(t_csound_tilde *x, t_signal **sp)
{
    int                 nchannels = x->x_nchannels;
    int                 ninchannels  = x->x_outputflag ? nchannels : 1;  /* at least default signal inlet */
    t_perfroutine       perf_routine;
    int                 i;

    CSD_DEBUG_CALL(post("DEBUG csound_tilde_dsp"));

    csound_tilde_free_buffers(x);
    
    /* set up I/O buffer */
    x->x_buf_byte_count = sp[0]->s_n * nchannels * sizeof(float);

    if ((nchannels > 1) || (sizeof(t_sample) != sizeof(float))) {
        x->x_buf = getbytes(x->x_buf_byte_count);
    }

    /* set up dsp performance code, optimize the common cases */
    switch (nchannels) {
    case 1:
        if (x->x_buf) {
            CSD_DEBUG_CALL(post("DEBUG csound~ (dsp): sizeof(t_sample) != sizeof(float), copy in perf"));
            perf_routine = csound_tilde_perf_1_copy;
        } else {
            perf_routine = csound_tilde_perf_1; 
        }
        break;
    case 2:
        perf_routine = csound_tilde_perf_2;
        break;
    default:
        perf_routine = csound_tilde_perf_many;
    }

    x->x_vec_frame_count = sp[0]->s_n;

    for (i = 0; i < ninchannels; i++) {
        x->x_invec[i] = sp[i]->s_vec;
    }

    for (i = 0; i < nchannels; i++) {
        x->x_outvec[i] = sp[ninchannels+i]->s_vec;
    }

    dsp_add(perf_routine, 1, x);
}


/* +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
   + class methods
   +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */

static void*
csound_tilde_new(t_floatarg fnchannels, t_floatarg foutputflag)
{
    t_csound_tilde      *x;
    int                 nchannels = fnchannels;
    int                 outputflag = (int)foutputflag == 0 ? 0 : 1;
    int                 i;

    if (nchannels <= 0) {
        post("csound~ (new): number of channels was %d, set to 1", nchannels);
        nchannels = 1;
    }

    if (nchannels > CSD_MAX_NUM_CHANNELS) {
        post("csound~ (new): number of channels was %d, set to %d", nchannels, CSD_MAX_NUM_CHANNELS);
        nchannels = CSD_MAX_NUM_CHANNELS;
    }

    x = (t_csound_tilde *)pd_new(csound_tilde_class);

    if (outputflag) {
        for (i = 1; i < nchannels; i++) {
            inlet_new(&x->x_obj, &x->x_obj.ob_pd, &s_signal, &s_signal);
        }
    }

    for (i = 0; i < nchannels; i++) {
        outlet_new(&x->x_obj, &s_signal);
    }

    x->x_f                      = 0;

    x->x_canvas                 = canvas_getcurrent();

    *x->x_evt_out_filename      = '\0';
    x->x_evt_out_fd             = -1;

    *x->x_snd_out_filename      = '\0';
    x->x_snd_out_fd             = -1;

    *x->x_snd_in_filename       = '\0';
    x->x_snd_in_fd              = -1;

    x->x_csound_bin_filename    = NULL;
    x->x_csound_orc_filename    = NULL;
    x->x_csound_sco_filename    = NULL;

    x->x_pid                    = -1;
    x->x_paused                 = 1;

    x->x_nchannels              = nchannels;
    x->x_outputflag             = outputflag;
    x->x_buf                    = NULL;

    return (void *)x;
}

static void
csound_tilde_free(t_csound_tilde *x)
{
    CSD_DEBUG_CALL(post("DEBUG csound~: csound_tilde_free"));
    csound_tilde_free_buffers(x);
    csound_tilde_close(x);
}


/* +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
   + library initialization
   +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */

void
csound_tilde_setup(void) 
{
    post("                                        ");
    post(" ^                                      ");
    post(" | .*~*.  csound~ %s                    ", CSD_VERSION);
    post(" |/     \\ ( c ) 2002 orm finnendahl    ");
    post(" +-------*-------- + stefan kersten --->");
    post(" |        \\     /                      ");
    post(" |         °. .°                        ");
    post("                                        ");

    csound_tilde_class = class_new(gensym("csound~"),
				   (t_newmethod)csound_tilde_new,
				   (t_method)csound_tilde_free, 
                                   sizeof(t_csound_tilde),
				   CLASS_DEFAULT, A_DEFFLOAT, A_DEFFLOAT, 0);

    class_addmethod(csound_tilde_class,
		    (t_method)csound_tilde_dsp, gensym("dsp"), 0);

    class_addmethod(csound_tilde_class, 
		    (t_method)csound_tilde_csound, gensym("csound"), A_GIMME, A_NULL);
    class_addmethod(csound_tilde_class, 
		    (t_method)csound_tilde_close, gensym("close"), A_NULL);
    class_addmethod(csound_tilde_class, 
                    (t_method)csound_tilde_pause, gensym("pause"), A_NULL);

    class_addmethod(csound_tilde_class,
		    (t_method)csound_tilde_status, gensym("status"), A_NULL);
    class_addmethod(csound_tilde_class,
		    (t_method)csound_tilde_help, gensym("help"), A_NULL);

    class_addmethod(csound_tilde_class, 
		    (t_method)csound_tilde_bin, gensym("bin"), A_SYMBOL, A_NULL);
    class_addmethod(csound_tilde_class,
                    (t_method)csound_tilde_orc, gensym("orc"), A_SYMBOL, A_NULL);
    class_addmethod(csound_tilde_class, 
                    (t_method)csound_tilde_sco, gensym("sco"), A_SYMBOL, A_NULL);

    class_addbang(csound_tilde_class, csound_tilde_bang);
    class_addlist(csound_tilde_class, csound_tilde_list);
    class_addanything(csound_tilde_class, csound_tilde_anything);

    CLASS_MAINSIGNALIN(csound_tilde_class, t_csound_tilde, x_f);
}

/* EOF */
