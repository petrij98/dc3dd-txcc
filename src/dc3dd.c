// dc3dd -- a dd for digital forensics.
//   Copyright (C) 85, 90, 91, 1995-2008 Free Software Foundation, Inc.
//
//   This program is free software: you can redistribute it and/or modify
//   it under the terms of the GNU General Public License as published by
//   the Free Software Foundation, either version 3 of the License, or
//   (at your option) any later version.
//
//   This program is distributed in the hope that it will be useful,
//   but WITHOUT ANY WARRANTY; without even the implied warranty of
//   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//   GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//   along with this program.  If not, see <http://www.gnu.org/licenses/>.

//-------------------------
// INCLUDES
//-------------------------

#include <config.h> // NOTE: "config.h" must be first include
#include <sys/types.h>
#include <signal.h>
#include <getopt.h>
#include <stdarg.h>
#include <pthread.h>
#include "system.h"
#include "error.h"
#include "gethrxtime.h"     
#include "human.h"
#include "long-options.h"
#include "quote.h"
#include "quotearg.h"
#include "xstrtol.h"
#include "xtime.h"
#include "md5.h"
#include "sha1.h"
#include "sha256.h"
#include "sha512.h"

#ifdef __linux__
   #include <sys/mount.h>
   #include <sys/mtio.h>
   #ifdef USE_HDPARM
   #include <linux/types.h>
   #include "hdparm/hpa_dco.h"
   #endif
#elif defined (__APPLE__)
   #include <sys/disk.h>
   #include <sys/ioctl.h>
#elif defined (__CYGWIN__)
   #include <sys/ioctl.h>
   //#include <cygwin/types.h>
   #include <sys/types.h>
   #include <cygwin/fs.h>
#endif

//-------------------------
// #DEFINES
//-------------------------

#define PROGRAM_NAME "dc3dd"

#define AUTHORS \
  proper_name("Paul Rubin"), \
  proper_name("David MacKenzie"), \
  proper_name("Stuart Kemp"), \
  proper_name("Jesse Kornblum"), \
  proper_name("Andrew Medico"), \
  proper_name("Richard Cordovano"), \
  proper_name("Justin Lowe")

// Keep block size smaller than SIZE_MAX - alignment bytes, to allow
// allocating buffers that size. Keep block size smaller than SSIZE_MAX, for 
// the benefit of system calls like read(). And keep block size smaller than
// OFF_T_MAX, for the benefit of lseek().
#define MAX_BLOCKSIZE() MIN (SIZE_MAX - (2 * getpagesize() - 1), MIN (SSIZE_MAX, OFF_T_MAX))

#define STRINGIFY(s) #s
#define AS_STRING(s) STRINGIFY(s)

#define DC3DD_ASSERT(c) {if (!(c)) report_program_error((#c));}

//-------------------------
// CONSTANTS
//-------------------------

static const size_t DEFAULT_SECTOR_SIZE = 512;
static const size_t DEFAULT_BUFFER_SIZE = 32768;
static const uint8_t NUM_BUFFERS = 64;
static const uint8_t NUM_HASHES = 4;
static const uintmax_t INFINITE_BYTES = (uintmax_t)-1;
static const uintmax_t INFINITE_SECTORS = (uintmax_t)-1;
static const mode_t OUTPUT_FILE_PERMS = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
static const int FILE_DESCRIPTOR_NOT_SET = -2;
static const size_t DISPLAY_MESSAGE_LENGTH = 4096; 
static const long int JOB_PROGRESS_INTERVAL_MILLISECS = 100; 

//-------------------------
// ENUMS
//-------------------------

enum LOGS {
   ALL_LOGS,
   JOB_LOGS,
   HASH_LOGS,
   MACH_LOGS,
   HASH_LOGS_NO_DISPLAY
};

enum IO_STATE {
   PENDING,
   OPEN,
   COMPLETE,
   FATAL_ERROR
};

enum EXIT_CODE {
   DC3DD_EXIT_CODE_NOT_SET = -1,
   DC3DD_EXIT_COMPLETED,
   DC3DD_EXIT_ABORTED,
   DC3DD_EXIT_FAILED,
};

enum VERIFICATION_TYPE {
   NONE,
   STANDARD,
   DEVICE_PARTIAL,
   DEVICE_FULL
};

//-------------------------
// TYPEDEFS
//-------------------------

typedef struct _log_t {
   FILE *file;
   struct _log_t *next_log;
} log_t;

typedef struct _file_t {
   char *unparsed_name;
   char *name;
   bool part_of_set;
   uintmax_t number;
   int flags;
   int descriptor;
   intmax_t offset;
   bool probed;
   uintmax_t probed_size_in_bytes;
   uintmax_t probed_size_in_sectors;
   size_t probed_sector_size;
   bool is_device;
   bool is_block_device;
   uintmax_t bytes_processed;
   enum VERIFICATION_TYPE verification;
   struct _file_t *next_file;
} file_t;

typedef struct _settings_t {
   char *input_pattern_string;
   char *input_pattern;
   size_t input_pattern_length;
   file_t *input_file;
   file_t *output_files;
   file_t *wipe_target;
   size_t sector_size;
   const char * sector_size_source;
   size_t buffer_size;
   uintmax_t input_sectors_to_skip;
   uintmax_t output_sectors_to_skip;
   uintmax_t max_sectors_to_input;
   uintmax_t max_output_file_size;
   bool recover_errors; 
   bool splitting_output;
   bool verifying_output;
   bool append_output;
   bool corrupt_output;
} settings_t;

typedef void hash_init_func_t(void* ctx);
typedef void hash_update_func_t(const void* buf, size_t len, void* ctx);
typedef void hash_finish_func_t(void* ctx, void* buf);

typedef struct _hash_algorithm_t {
   bool active;
   char *name;
   size_t context_size;
   size_t sum_size;
   hash_init_func_t *init;
   hash_update_func_t *update;
   hash_finish_func_t *finish;
} hash_algorithm_t;

typedef struct _hash_t {
   void *context;
   char *sum;
   char *result;
   uintmax_t bytes_hashed;
   struct _hash_t *next_hash;
} hash_t;

typedef struct _buffer_t {
   char *data;
   size_t length;
} buffer_t;

typedef struct _buffer_queue_t {
   buffer_t *buffers;
   uint number_of_buffers;
   uint buffers_used;
   uint next_available_buffer;
   pthread_mutex_t *lock;
   pthread_cond_t *not_empty;
   pthread_cond_t *not_full;
   bool done_buffering;
} buffer_queue_t;

typedef struct _input_t {
   enum IO_STATE state;
   size_t buffer_size;
   buffer_t buffer;
   size_t sector_size;
   uint64_t max_sectors_to_input; 
   uint64_t bytes_to_input;
   uint64_t bytes_input;
   file_t* current_file;
   file_t* files;   
   uint64_t sectors_to_skip;
   uint64_t current_sector;
   bool recover_errors;
   int current_errno;
   uint64_t current_errno_count;
   uint64_t current_errno_start_sector;
   uint64_t bad_sectors;   
   char* pattern_string;
   char* pattern;
   size_t pattern_length;
   void (*open)(struct _input_t* input);
   void (*produce_bytes)(struct _input_t* input);
   void (*close)(struct _input_t* input);
} input_t;

typedef struct _hash_output_t {
   hash_algorithm_t *algorithm;
   hash_t *total_hash;
   uint64_t total_hash_length;
   hash_t *current_piece;
   hash_t *piecewise_hash;
   uint64_t piecewise_hash_length;
   hash_t *device_hash;
   struct _hash_output_t *next;
} hash_output_t;

typedef struct _file_output_t {
   file_t* current_file;
   file_t* files;
   uint64_t max_file_size;
   uint64_t sectors_to_skip;
   uint64_t bytes_output;
   enum VERIFICATION_TYPE verification;
   hash_output_t* expected_hashes;
   hash_output_t* actual_hashes;
   bool append_garbage_bytes; // For testing purposes.
} file_output_t;

typedef struct _output_t {
   enum IO_STATE state; 
   pthread_t thread;
   size_t sector_size;
   uint64_t buffer_size;
   buffer_queue_t* buffer_queue;
   hash_output_t *hash;
   file_output_t *file;
   bool machine;
   void (*open)(struct _output_t* output);
   void (*consume_bytes)(struct _output_t* output, buffer_t* buffer);
   void (*close)(struct _output_t* output);
   struct _output_t* next_output;   
} output_t;

typedef struct _task_t {
   pthread_t thread;
   pthread_mutex_t *signaling_lock;
   input_t *input;
   output_t *outputs;
   file_output_t *verification_target;
   bool completed;
   bool aborted;
   enum EXIT_CODE exit_code;
   struct _task_t *next_task;   
} task_t;

typedef struct _job_t {
   pthread_t monitor_thread;
   task_t* tasks;
   long int progress_interval_in_ms;
   void (*report_progress)(struct _job_t* job, bool final);
   enum EXIT_CODE exit_code;
   struct _job_t* next_job;
} job_t;

//-------------------------
// GLOBAL VARIABLES
//-------------------------

char *program_name = NULL;
static xtime_t start_time;
static xtime_t start_time_verification;
static bool verification_task_started = false;
static log_t *job_logs = NULL;
static log_t *hash_logs = NULL;
static bool machine_report = false;
static log_t *mach_logs = NULL;
static log_t *all_logs = NULL;
static bool progress_displayed = false;
static pthread_mutex_t signaling_lock;
static pthread_cond_t *interrupted = 0;

#ifdef DEFAULT_VERBOSE_REPORTING
static bool verbose_reporting = true;
#else
static bool verbose_reporting = false;
#endif

#ifdef DEFAULT_COMPACT_REPORTING
static bool compact_reporting = true;
#else
static bool compact_reporting = false;
#endif

#ifdef DEFAULT_BASE_TEN_BYTES_REPORTING
static int progress_bytes_reporting_flag = 0;
#else
static int progress_bytes_reporting_flag = human_base_1024;
#endif

// A single lock is used for both the job_logs and the console so that the 
// ordering of the log messages will be the same on the console and in the
// logs.  
static pthread_mutex_t reporting_lock;

// Currently supporting MD5, SHA1, SHA256, and SHA512.
static hash_algorithm_t hash_algorithms[] = {
   { 
      #ifdef DEFAULT_HASH_MD5
      true,
      #else
      false,
      #endif
      "md5",
      sizeof(struct md5_ctx),
      16,
      (hash_init_func_t*)md5_init_ctx,
      (hash_update_func_t*)md5_process_bytes,
      (hash_finish_func_t*)md5_finish_ctx,
   },
   {
      #ifdef DEFAULT_HASH_SHA1
      true,
      #else
      false,
      #endif
      "sha1",
      sizeof(struct sha1_ctx),
      20,
      (hash_init_func_t*)sha1_init_ctx,
      (hash_update_func_t*)sha1_process_bytes,
      (hash_finish_func_t*)sha1_finish_ctx,
   },
   {
      #ifdef DEFAULT_HASH_SHA256
      true,
      #else
      false,
      #endif
      "sha256",
      sizeof(struct sha256_ctx),
      32,
      (hash_init_func_t*)sha256_init_ctx,
      (hash_update_func_t*)sha256_process_bytes,
      (hash_finish_func_t*)sha256_finish_ctx,
   },
   {
      #ifdef DEFAULT_HASH_SHA512
      true,
      #else
      false,
      #endif
     "sha512",
      sizeof(struct sha512_ctx),
      64,
      (hash_init_func_t*)sha512_init_ctx,
      (hash_update_func_t*)sha512_process_bytes,
      (hash_finish_func_t*)sha512_finish_ctx,
   }
};

//-------------------------
// FUNCTIONS
//-------------------------

void usage(int status);

static void
terminate_logging() {
   pthread_mutex_lock(&reporting_lock);

   for (log_t *log = all_logs; log; log = log->next_log) {
      fflush(log->file);
      fclose(log->file);
   }   

   pthread_mutex_unlock(&reporting_lock);
   pthread_mutex_destroy(&reporting_lock);
}

static void
flush_logs() {
   fflush(stderr);
   for (log_t *log = all_logs; log; log = log->next_log)
      fflush(log->file);
}

static void
write_to_logs(const char *message, enum LOGS target) {
   log_t *logs = NULL;
   switch (target) {
      case ALL_LOGS:
         logs = all_logs;
         break;
      case JOB_LOGS:
         logs = job_logs;
         break;
      case HASH_LOGS:
         logs = hash_logs ? hash_logs : job_logs;
         break;
      case MACH_LOGS:
	 logs = mach_logs ? mach_logs : job_logs;
	 break;
	  /* WB - New */
      case HASH_LOGS_NO_DISPLAY:
         logs = hash_logs;
         break;
   }

   for (log_t *log = logs; log; log = log->next_log)
      fputs(message, log->file);
}

static void
report(const char *message, enum LOGS target) {
   pthread_mutex_lock(&reporting_lock);
   /* WB - Don't display message if this enum is set */
   if (target != HASH_LOGS_NO_DISPLAY)
       fputs(message, stderr);   
   write_to_logs(message, target);

   pthread_mutex_unlock(&reporting_lock);
}

// Begin code copied (and modified) from ../lib/error.c 

#define __strerror_r strerror_r

static void
append_system_error_message(int errnum) {
   char const *s = NULL;

  // Attempt to get the current error string.
#if defined HAVE_STRERROR_R || _LIBC
   char errbuf[DISPLAY_MESSAGE_LENGTH];
  #if STRERROR_R_CHAR_P || _LIBC
   s = __strerror_r(errnum, errbuf, sizeof errbuf);
  #else
   if (__strerror_r(errnum, errbuf, sizeof errbuf) == 0)
      s = errbuf;
   else
      s = NULL;
  #endif
#else
   s = strerror(errnum);
#endif

  // Use a generic error string if the attempt to get the system error
  // system string failed.
#if !_LIBC
   if (!s)
      s = _("system error");
#endif

#if _LIBC
   __fxprintf(NULL, ": %s", s);
#else
   fprintf(stderr, ": %s", s);
#endif
   for (log_t* log = job_logs; log; log = log->next_log)
      fprintf(log->file, ": %s", s);
}

static void
write_error_message(int errnum, const char *message, va_list args)
{
   va_list arg2;
   va_copy(arg2, args);

   // Write the error message.
#if _LIBC
   if (_IO_fwide (stderr, 0) > 0)
   {
      // Write the message using wide chars.
      #define ALLOCA_LIMIT 2000
      size_t len = strlen(message) + 1;
      wchar_t *wmessage = NULL;
      mbstate_t st;
      size_t res;
      const char *tmp;
      bool use_malloc = false;
      
      while (1)
      {
         if (__libc_use_alloca(len * sizeof (wchar_t)))
            wmessage = (wchar_t *)alloca(len * sizeof (wchar_t));
         else
         {
            if (!use_malloc)
               wmessage = NULL;

            wchar_t *p = (wchar_t *)realloc(wmessage, len * sizeof (wchar_t));
            if (p == NULL)
            {
               free (wmessage);
               fputws_unlocked(L"out of memory\n", stderr);
               return;
            }
            wmessage = p;
            use_malloc = true;
         }

         memset(&st, '\0', sizeof (st));
         tmp = message;
         res = mbsrtowcs(wmessage, &tmp, len, &st);
         if (res != len)
            break;

         if (__builtin_expect(len >= SIZE_MAX / 2, 0))
         {
            res = (size_t)-1;
            break;
         }

         len *= 2;
      }

      if (res == (size_t)-1)
      {
         // The string cannot be converted. 
         if (use_malloc)
         {
            free (wmessage);
            use_malloc = false;
         }
         wmessage = (wchar_t *) L"???";
      }

      __vfwprintf(stderr, wmessage, args);
      for (log_t *log = job_logs; log; log = log->next_log)
         __vfwprintf(log->file, wmessage, arg2);
      
      if (use_malloc)
         free(wmessage);
   }
   else
#endif
   {
      // Write the message using standard chars.
      vfprintf(stderr, message, args);
      for (log_t *log = job_logs; log; log = log->next_log)
         vfprintf(log->file, message, arg2);
   }

  va_end(args);
  
   ++error_message_count;
   if (errnum)
      append_system_error_message(errnum);

   // Finish off the error message with a newline.   
#if _LIBC
   __fxprintf(NULL, "\n");
#else
   putc('\n', stderr);
#endif
   fflush(stderr);
   for (log_t *log = job_logs; log; log = log->next_log) {
         putc('\n', log->file);
         fflush(log->file);
   }
}

static void 
report_error(int status, int errnum, const char *message, ...)
{
   pthread_mutex_lock(&reporting_lock);

   // Disable thread cancellation and lock stderr.
#ifdef _LIBC
  #ifdef __libc_ptf_call
   int state = PTHREAD_CANCEL_ENABLE;
   __libc_ptf_call (pthread_setcancelstate, (PTHREAD_CANCEL_DISABLE, &state), 0);
  #endif
   _IO_flockfile (stderr);
#endif

   // Prefix the error message with an attention grabbing character sequence.
#if _LIBC
   __fxprintf (NULL, "%s[!!] ", progress_displayed ? "\n" : "");
#else
   fprintf (stderr, "%s[!!] ", progress_displayed ? "\n" : "");
#endif
   write_to_logs("[!!] ", JOB_LOGS); 

   va_list args;
   va_start(args, message);
   write_error_message(errnum, message, args);

   // Enable thread cancellation and unlock stderr.
#ifdef _LIBC
   _IO_funlockfile (stderr);
  # ifdef __libc_ptf_call
   __libc_ptf_call (pthread_setcancelstate, (state, NULL), 0);
  #endif
#endif

   pthread_mutex_unlock(&reporting_lock);

   if (status)
      usage(status); 
}

// End code copied (and modified) from ../lib/error.c 

static char*
get_formatted_time_string()
{
   // Get the current local time.
   time_t t = time(NULL);
   struct tm tm;
   struct tm* ret = localtime_r(&t, &tm);
   if (ret == NULL)
      report_error(DC3DD_EXIT_ABORTED, errno, "localtime() failed");

   // Put it in string form.
   const size_t len = 32; // More than enough to hold 'YYYY-MM-DD HH:MM:SS -0000'
   char* time_str = (char*)malloc(len);
   if (strftime(time_str, len, "%F %T %z", &tm) == 0)
      report_error(DC3DD_EXIT_ABORTED, 0, "strftime() returned 0");

   return time_str;
}

static void
report_exit_message(int exit_code)
{
   // Translate the exit code into a printable word.
   const char* verb = NULL;
   switch (exit_code) {
      case DC3DD_EXIT_COMPLETED:
          verb = _("completed");
          break;
      case DC3DD_EXIT_ABORTED:
          verb = _("aborted");
          break;
      case DC3DD_EXIT_FAILED:
      case DC3DD_EXIT_CODE_NOT_SET: 
      default:
          verb = _("failed");
          break;
   }

   // Write the exit message to all logs as a sort of footer for the run.
   char* formatted_stop_time = get_formatted_time_string();
   char message[DISPLAY_MESSAGE_LENGTH];
   sprintf(message, _("%s %s at %s\n\n"), PROGRAM_NAME, verb, formatted_stop_time);
   free(formatted_stop_time);
   report(message, ALL_LOGS);
   flush_logs();
}

static void
report_program_error(const char* assertion)
{
   char internal_error[DISPLAY_MESSAGE_LENGTH];
   sprintf(internal_error, _("%s: internal error %s at line %d"), program_name, assertion, __LINE__);
   write_to_logs(internal_error, JOB_LOGS);
   report_exit_message(DC3DD_EXIT_ABORTED);
   terminate_logging();
   emit_bug_reporting_address();
   exit(DC3DD_EXIT_ABORTED);
}

static void
report_output_hashes(output_t* output)
{
   char message[DISPLAY_MESSAGE_LENGTH];

   // Report the parallel hash lists stashed in the output struct.
   hash_output_t *actual_hash = output->file->actual_hashes;
   hash_output_t *expected_hash = output->file->expected_hashes;
   while (actual_hash && expected_hash) { 
      // Report the verification hash match/mismatch.
      sprintf(message, _("   %s %s (%s)\n"), 
	 STREQ(actual_hash->total_hash->result, expected_hash->total_hash->result) 
            ?  _("[ok]") : _("[MISMATCH]"),
	 actual_hash->total_hash->result,
	 actual_hash->algorithm->name);
        /* WB - correction code */
	if (job_logs != NULL) {
	    report(message, JOB_LOGS);
	    if (hash_logs != NULL) {
		report(message,HASH_LOGS_NO_DISPLAY);
	    }
	}
	else {
	    report(message,HASH_LOGS);
	}
        /***********************/

     // Report piecewise hashes, if any.
     if (output->file->files) {
	uintmax_t start_sector = 0;
	file_t* file = output->file->files;
	hash_t* actual_piece = actual_hash->piecewise_hash;
	hash_t* expected_piece = expected_hash->piecewise_hash;
	while (file && actual_piece && expected_piece) {
	   // For a file set, report piecewise hash matches/mismatches,
	   // indented two levels.
	   sprintf(message, _("      %s %s, sectors %"PRIuMAX" - %"PRIuMAX", %s\n"), 
	      STREQ(actual_piece->result, expected_piece->result) ?  _("[ok]") : _("[MISMATCH]"),
	      actual_piece->result,
	      start_sector,
	      start_sector + actual_piece->bytes_hashed / output->sector_size - 1,
	      quote(file->name));
	   report(message, HASH_LOGS);

	   start_sector += actual_piece->bytes_hashed / output->sector_size;
	   file = file->next_file;
	   actual_piece = actual_piece->next_hash;
	   expected_piece = expected_piece->next_hash;
	}
     }

     actual_hash = actual_hash->next;
     expected_hash = expected_hash->next;
   }

   if (output->file->verification == DEVICE_FULL) {
      hash_output_t *actual_hash = output->file->actual_hashes;
      hash_output_t *expected_hash = output->file->expected_hashes;

      // Compute the the number of bytes hashed beyond those that dc3dd wrote. 
      uintmax_t additional_bytes = 
         actual_hash->device_hash->bytes_hashed - actual_hash->total_hash->bytes_hashed;
      uintmax_t sectors = additional_bytes / output->sector_size;
      uintmax_t leftover_bytes = additional_bytes % output->sector_size;

      // Write the results of the computation as a header for the additional hashes.
      if (leftover_bytes == 0)
         sprintf(message, _("   additional %"PRIuMAX" sectors of device hashed\n"), sectors);
      else
         sprintf(message, _("   additional %"PRIuMAX" sectors + %"PRIuMAX" bytes of device hashed\n "), 
            sectors, leftover_bytes);
      /* WB - correction code */
      if (job_logs != NULL) {
          report(message, JOB_LOGS);
          if (hash_logs != NULL) {
              report(message,HASH_LOGS_NO_DISPLAY);
          }
      }
      else {
          report(message,HASH_LOGS);
      }
      /***********************/

      while (actual_hash && expected_hash) { 
         sprintf(message, _("   %s (device total %s)\n"), actual_hash->device_hash->result, actual_hash->algorithm->name);
         /* WB - correction code */
         if (job_logs != NULL) {
             report(message, JOB_LOGS);
             if (hash_logs != NULL) {
                 report(message,HASH_LOGS_NO_DISPLAY);
             }
         }
         else {
             report(message,HASH_LOGS);
         }
         /***********************/
         actual_hash = actual_hash->next;
         expected_hash = expected_hash->next;
      }
   }
}

static void
report_machine_output_hashes(output_t* output)
{
   char message[DISPLAY_MESSAGE_LENGTH];

static  long unsigned first_sector=0, last_sector=0;

   // Report the parallel hash lists stashed in the output struct.
   hash_output_t *actual_hash = output->file->actual_hashes;
   hash_output_t *expected_hash = output->file->expected_hashes;
   while (actual_hash && expected_hash) { 
      // Report the verification hash match/mismatch.
/** DM ********/

     // Report piecewise hashes, if any.
     if (output->file->files) {
	uint64_t start_sector = 0;
	file_t* file = output->file->files;
	hash_t* actual_piece = actual_hash->piecewise_hash;
	hash_t* expected_piece = expected_hash->piecewise_hash;
	while (file && actual_piece && expected_piece) {
	   // For a file set, report piecewise hash matches/mismatches,
	   // indented two levels.
	   sprintf(message, _("       %s| sectors (%s) | %12"PRIuMAX"| %12"PRIuMAX"| %s | %s\n"), 
	      actual_piece->result,
    actual_hash->algorithm->name,
	      start_sector,
	      start_sector + actual_piece->bytes_hashed / output->sector_size - 1,
	      quote(file->name),
	      STREQ(actual_piece->result, expected_piece->result) ?  _("[ok]") : _("[MISMATCH]")  );
	   report(message, MACH_LOGS);

	   start_sector += actual_piece->bytes_hashed / output->sector_size;
	   file = file->next_file;
	   actual_piece = actual_piece->next_hash;
	   expected_piece = expected_piece->next_hash;
last_sector = start_sector-1;
	}
     }

/** DM  this is the final value of the entire item/disk ********/
/*  moved from above where it was first, not last in the list */
/*  added first and last sector for entire drive, so grepping is possible */
      sprintf(message, _("       %s| sectors (%s) | %12"PRIuMAX"| %12"PRIuMAX"| FINAL: %s | %s\n"), 
	 actual_hash->total_hash->result,
    actual_hash->algorithm->name,
	 first_sector, last_sector, 
    actual_hash->algorithm->name,
	 STREQ(actual_hash->total_hash->result, expected_hash->total_hash->result) ?  _("[OK]") : _("[MISMATCH]"));
      report(message, MACH_LOGS);
/** DM ********/


     actual_hash = actual_hash->next;
     expected_hash = expected_hash->next;
   }

   if (output->file->verification == DEVICE_FULL) {
      hash_output_t *actual_hash = output->file->actual_hashes;
      hash_output_t *expected_hash = output->file->expected_hashes;

      // Compute the the number of bytes hashed beyond those that dc3dd wrote. 
      uint64_t additional_bytes = 
         actual_hash->device_hash->bytes_hashed - actual_hash->total_hash->bytes_hashed;
      uint64_t sectors = additional_bytes / output->sector_size;
      uint64_t leftover_bytes = additional_bytes % output->sector_size;

      // Write the results of the computation as a header for the additional hashes.
      if (leftover_bytes == 0)
         sprintf(message, _("   additional %"PRIuMAX" sectors of device hashed\n"), sectors);
      else
         sprintf(message, _("   additional %"PRIuMAX" sectors + %"PRIuMAX" bytes of device hashed\n "), 
            sectors, leftover_bytes);
      report(message, MACH_LOGS);

      while (actual_hash && expected_hash) { 
         sprintf(message, _("   %s (device total %s)\n"), actual_hash->device_hash->result, actual_hash->algorithm->name);
         report(message, MACH_LOGS);
         actual_hash = actual_hash->next;
         expected_hash = expected_hash->next;
      }
   }
}

static void
report_input_hashes(output_t* output)
{
   char message[DISPLAY_MESSAGE_LENGTH];

   // Report the verification hash.
   sprintf(message, _("   %s (%s)\n"),
      output->hash->total_hash->result, output->hash->algorithm->name);
   /* WB - correction code */
   if (job_logs != NULL) {
      if (hash_logs != NULL) {
         report(message,HASH_LOGS_NO_DISPLAY);
      }
      report(message, JOB_LOGS);
   }
   else {
      report(message,HASH_LOGS);
   }
   /***********************/

   // Report any piecewise hashes.
   uintmax_t start_sector = 0;
   for (hash_t *piece = output->hash->piecewise_hash; piece; piece = piece->next_hash) {
      sprintf(message, _("      %s, sectors %"PRIuMAX" - %"PRIuMAX"\n"),
         piece->result,
         start_sector,
         start_sector + piece->bytes_hashed / output->sector_size - 1);
      report(message, HASH_LOGS);
      start_sector += piece->bytes_hashed / output->sector_size;
   }
}

static void
report_machine_input_hashes(output_t* output)
{
   char message[DISPLAY_MESSAGE_LENGTH];
static  long unsigned first_sector=0, last_sector=0;

   // Report the verification hash.
/* DM moved this down to bottom of list */

   // Report any piecewise hashes.
   uint64_t start_sector = 0;
   for (hash_t *piece = output->hash->piecewise_hash; piece; piece = piece->next_hash) {
      sprintf(message, _("       %s| sectors (%s) | %12"PRIuMAX"| %12"PRIuMAX"\n"),
         piece->result,
			output->hash->algorithm->name,
         start_sector,
         start_sector + piece->bytes_hashed / output->sector_size - 1);
      report(message, MACH_LOGS);
      start_sector += piece->bytes_hashed / output->sector_size;
last_sector = start_sector-1;
   }

/* DM moved down to here */
   sprintf(message, _("       %s| (FINAL: %s)  | %12"PRIuMAX"| %12"PRIuMAX" \n"),
      output->hash->total_hash->result, output->hash->algorithm->name, first_sector, last_sector );
   report(message, MACH_LOGS);

}

static void
report_files_IO(file_t* files, size_t sector_size, bool is_input)
{
   char message[DISPLAY_MESSAGE_LENGTH];

   for (file_t *file = files; file; file = file->next_file) {
      uint64_t sectors = file->bytes_processed / sector_size;
      uint64_t leftover_bytes = file->bytes_processed % sector_size;
      if (leftover_bytes == 0)
	 sprintf(message,
             _("      %"PRIuMAX" sectors %s %s\n"),
            sectors, is_input ? _("in from") : _("out to"),
            quote(file->name));
      else
	 sprintf(message,
             _("      %"PRIuMAX" sectors + %"PRIuMAX" bytes %s %s\n"), 
	    sectors, leftover_bytes, 
            is_input ?  _("in from") : _("out to"), quote(file->name));
      report(message, JOB_LOGS);
   }
}

static void
report_file_IO(file_t* file, uint64_t bytes, size_t sector_size, bool is_input)
{
   char message[DISPLAY_MESSAGE_LENGTH];

   // Write the file name.
   sprintf(message, "%s results for %s %s:\n",
      is_input ? _("input") : _("output"),
      file->is_device ? _("device") : file->part_of_set ? _("files") : _("file"),
      quote(file->unparsed_name));   
   report(message, ALL_LOGS);
   
   // Write the number of the sectors read or written.
   uint64_t sectors = bytes / sector_size;
   uint64_t leftover_bytes = bytes % sector_size;
   if (leftover_bytes == 0)
      sprintf(message, _("   %"PRIuMAX" sectors %s\n"), sectors, is_input ? _("in") : _("out"));
   else
      sprintf(message, _("   %"PRIuMAX" sectors + %"PRIuMAX" bytes %s\n"), 
         sectors, leftover_bytes, is_input ? _("in") : _("out"));
   report(message, JOB_LOGS);
}

static void 
report_file_output(output_t* output)
{
   file_output_t *file_output = output->file;
   report_file_IO(file_output->current_file, file_output->bytes_output, output->sector_size, false);
   if (verbose_reporting)
      report_files_IO(file_output->files, output->sector_size, false);
}

static void 
report_input(input_t* input)
{
   char message[DISPLAY_MESSAGE_LENGTH];   
   if (input->current_file) {
      // Report file input stats.
      report_file_IO(input->current_file, input->bytes_input, input->sector_size, true);

      if (input->current_file->is_device) {
	 sprintf(message, _("   %"PRIuMAX" bad sectors replaced by zeros\n"), input->bad_sectors);
	 report(message, JOB_LOGS);
      }

      if (verbose_reporting)
         report_files_IO(input->files, input->sector_size, true);
   }
   else {
      // Report pattern input stats.
      sprintf(message, _("input results for pattern %s:\n"), quote(input->pattern_string));
      report(message, ALL_LOGS);
      sprintf(message, _("   %"PRIuMAX" sectors in\n"), input->bytes_input / input->sector_size); 
      report(message, ALL_LOGS);
   }
}

static void 
report_results(job_t* jobs)
{
   pthread_mutex_lock(&reporting_lock);

   // The first job is the imaging (or wiping) job, and there is only
   // one task in an imaging job.
   job_t* imaging_job = jobs;
   task_t* imaging_task = jobs->tasks;
   job_t* verification_job = imaging_job->next_job;

   // Report progress, this time setting the final flag so it 
   // is terminated with a newline character instead of a carriage
   // return character and is written to the log (if present)
   // as well as the console.
   imaging_job->report_progress(imaging_job, true);
   if (verification_job)
      verification_job->report_progress(verification_job, true);
   if (!compact_reporting) report("\n", ALL_LOGS);

   // Report input stats and hashes.
   report_input(imaging_task->input);   
   for (output_t* output = imaging_task->outputs;  output; output = output->next_output)
      if (output->hash)
	{
	 report_input_hashes(output);
	if(machine_report)
	{
		report_machine_input_hashes(output);
	}
	}
   if (!compact_reporting)
      report("\n", ALL_LOGS);

   // Report output stats and hashes. 
   for (output_t* output = imaging_task->outputs;  output; output = output->next_output)
      if (output->file)
      {
	 report_file_output(output);
	 if (output->file->verification != NONE &&
	     verification_job &&
	     verification_job->exit_code == DC3DD_EXIT_COMPLETED)         
	 {
	    report_output_hashes(output);
	 }             
	if (output->file->verification !=NONE && verification_job && verification_job->exit_code == DC3DD_EXIT_COMPLETED && machine_report)
	{
		report_machine_output_hashes(output);
	}
	 if (!compact_reporting)
            report("\n", ALL_LOGS);
      }
   
   pthread_mutex_unlock(&reporting_lock);
}

static void
report_verification_progress(job_t* job, bool final)
{
   // Calculate percent complete using the ratio of the bytes input for all of 
   // the tasks to the bytes to be input for all of the tasks. Synchronization 
   // of this read-only access to the task thread data is not required since 
   // exact calculations are not required for the progress bar.
   uint64_t bytes_input = 0;
   uint64_t bytes_to_input = 0;

   int human_opts = (human_autoscale | human_round_to_nearest | human_suppress_point_zero | human_space_before_unit | human_SI | progress_bytes_reporting_flag);
   //char stats[DISPLAY_MESSAGE_LENGTH];  //future? - saved in case we want to put hash calculation stats into 'stats' output
   char hbuf[LONGEST_HUMAN_READABLE + 1];
   char hbuf2[LONGEST_HUMAN_READABLE + 1];

   double delta_s = 0.0;
   char const *bytes_per_second = NULL;
   //uint64_t est_time_left = 0; //future capability
   xtime_t now = gethrxtime();

   //This finds the biggest job and uses it to calculate the hash progress
   uint64_t job_size_holder = 0;
   for (task_t* task = job->tasks; task; task = task->next_task) {
      if (task->input->bytes_to_input > job_size_holder) {
	   bytes_input = task->input->bytes_input;
	   bytes_to_input = task->input->bytes_to_input;
	   job_size_holder = bytes_to_input;
      }
   }
   float percent_complete = bytes_to_input ? 100.0f * (float)bytes_input / (float)bytes_to_input : 100.0f;

   //Set start time for verification task here, then flip 'started' flag so it doesn't reset it everytime
   if (!verification_task_started) {
      start_time_verification = gethrxtime();
      verification_task_started = true;
   }

   if (start_time_verification < now) {
      double XTIME_PRECISIONe0 = XTIME_PRECISION;
      uint64_t delta_xtime = now;
      delta_xtime -= start_time_verification;
      delta_s = delta_xtime / XTIME_PRECISIONe0;
      bytes_per_second =
         human_readable(bytes_input, hbuf, human_opts, XTIME_PRECISION, delta_xtime);
      //est_time_left = (bytes_to_input - bytes_input) / (bytes_input / delta_s); //future capability
   }
   else {
      delta_s = 0.0;
      bytes_per_second = _("Infinity B");
      //est_time_left  = 0; //future capability
   }

   pthread_mutex_lock(&reporting_lock);

   // TRANSLATORS: The two instances of "s" in this string are the SI
   //   symbol "s" (meaning second), and should not be translated.
   //
   //  This format used to be:
   //
   //  ngettext (", %g second, %s/s\n", ", %g seconds, %s/s\n", delta_s == 1)
   //
   //  but that was incorrect for languages like Polish.  To fix this
   //  bug we now use SI symbols even though they're a bit more
   //  confusing in English.
   
   fprintf(stderr, "%79s", "\r");
   if (bytes_to_input > 0) {
      fprintf(stderr, _("%12"PRIuMAX" bytes ( %3s ) hashed ( %2.0f%% ), %4.0f s, %s/s %s"), 
	      bytes_input, human_readable(bytes_input, hbuf2, human_opts, 1, 1),
	      percent_complete, delta_s, bytes_per_second, final ? "\n" : "\r");
      //fprintf(stderr, _("%12"PRIuMAX" bytes ( %3s ) hashed ( %2.0f%% ), %4.0f s, %s/s %"PRIu64"s left %s"), bytes_input, human_readable(bytes_input, hbuf2, human_opts, 1, 1), percent_complete, delta_s, bytes_per_second, est_time_left, final ? "\n" : "\r"); //future capability
      if (final) 
         for (log_t* log = job_logs; log; log = log->next_log)
            fprintf(log->file, _("%12"PRIuMAX" bytes ( %3s ) hashed ( %2.0f%% ), %g s, %s/s\n"), 
	      bytes_input, human_readable(bytes_input, hbuf2, human_opts, 1, 1),
	      percent_complete, delta_s, bytes_per_second);
   }
   else {
      fprintf(stderr, _("%12"PRIuMAX" bytes ( %3s ) hashed (??%%), %4.0f s, %s/s %s"),
	      bytes_input, human_readable(bytes_input, hbuf2, human_opts, 1, 1),
	      delta_s, bytes_per_second, final ? "\n" : "\r");
      if (final)
         for (log_t *log = job_logs; log; log = log->next_log)
            fprintf(log->file, _("%12"PRIuMAX" bytes ( %3s ) hashed (??%%), %g s, %s/s\n"),
	       bytes_input, human_readable(bytes_input, hbuf2, human_opts, 1, 1),
	       delta_s, bytes_per_second);
   }

   progress_displayed = true;

   pthread_mutex_unlock(&reporting_lock);
   //TODO: add a nice message saying to please wait in case the biggest 
   // hashing job finishes first
}

static void
report_imaging_progress(job_t* job, bool final)
{
   // There is only one task in an imaging job.
   task_t* task = job->tasks;

   int human_opts = (human_autoscale | human_round_to_nearest | human_suppress_point_zero | 
      human_space_before_unit | human_SI | progress_bytes_reporting_flag);
   char stats[DISPLAY_MESSAGE_LENGTH]; 
   char hbuf[LONGEST_HUMAN_READABLE + 1];

   pthread_mutex_lock(&reporting_lock);
   fprintf(stderr, "%79s", "\r");

   sprintf(stats, _("%12"PRIuMAX" bytes ( %3s ) copied"),
      task->input->bytes_input,
      human_readable(task->input->bytes_input, hbuf, human_opts, 1, 1));
   fputs(stats, stderr);
   if (final)
      write_to_logs(stats, JOB_LOGS);
   
   if (task->input->bytes_to_input != INFINITE_BYTES) {
      // Oddly, the %% format specifier has no effect if this is done with sprintf(). 
      float percent_complete =
         100.0f * ((float)task->input->bytes_input / (float)task->input->bytes_to_input);
      fprintf(stderr, " ( %2.0f%% )", percent_complete);   
      if (final)
         for (log_t *log = job_logs; log; log = log->next_log)
            fprintf(log->file, " ( %2.0f%% )", percent_complete);
   }
   else {
      fputs(" (??%)", stderr);   
      if (final) 
         write_to_logs(" (??%)", JOB_LOGS);
   }

   double delta_s = 0.0;
   char const *bytes_per_second = NULL;
   xtime_t now = gethrxtime();
   if (start_time < now) {
      double XTIME_PRECISIONe0 = XTIME_PRECISION;
      uint64_t delta_xtime = now;
      delta_xtime -= start_time;
      delta_s = delta_xtime / XTIME_PRECISIONe0;
      bytes_per_second =
         human_readable(task->input->bytes_input, hbuf, human_opts, XTIME_PRECISION, delta_xtime);
   }
   else {
      delta_s = 0.0;
      bytes_per_second = _("Infinity B");
   }

   // TRANSLATORS: The two instances of "s" in this string are the SI
   //   symbol "s" (meaning second), and should not be translated.
   //
   //  This format used to be:
   //
   //  ngettext (", %g second, %s/s\n", ", %g seconds, %s/s\n", delta_s == 1)
   //
   //  but that was incorrect for languages like Polish.  To fix this
   //  bug we now use SI symbols even though they're a bit more
   //  confusing in English.


   // DM  fprintf (stderr, _(", %g s, %s/s        %s"), delta_s, bytes_per_second, final ? "\n" : "\r");
   fprintf (stderr, _(", %4.0f s, %s/s %s"), delta_s, bytes_per_second, final ? "\n" : "\r");
   if (final)
      for (log_t *log = job_logs; log; log = log->next_log)
         fprintf (log->file, _(", %g s, %s/s\n"), delta_s, bytes_per_second);
   progress_displayed = true;

   pthread_mutex_unlock(&reporting_lock);
}

static void
add_to_log_list(log_t **list, log_t *new_log)
{
   if (*list) {
      for (log_t *log = *list; log; log = log->next_log)
         if (!log->next_log) {
            log->next_log = new_log;
            break;
         }
   }
   else
      *list = new_log;
}

static void
add_to_task_list(task_t **list, task_t *new_task)
{
   if (*list) {
      for (task_t *task = *list; task; task = task->next_task)
         if (!task->next_task) {
            task->next_task = new_task;
            break;
         }
   }
   else
      *list = new_task;
}

static void
add_to_output_list(output_t **list, output_t *new_output)
{
   if (*list) {
      for (output_t *output = *list; output; output = output->next_output)
         if (!output->next_output) {
            output->next_output = new_output;
            break;
         }
   }
   else
      *list = new_output;
}

static void
add_to_hash_output_list(hash_output_t **list, hash_output_t *new_item)
{
   if (*list) {
      for (hash_output_t *item = *list; item; item = item->next)
         if (!item->next) {
            item->next= new_item;
            break;
         }
   }
   else
      *list = new_item;
}

static void
add_to_file_list(file_t **list, file_t *new_file)
{
   if (*list) {
      for (file_t *file = *list; file; file = file->next_file)
         if (!file->next_file) {
            file->next_file = new_file;
            break;
         }
   }
   else
      *list = new_file;
}

static void
add_to_hash_list(hash_t **list, hash_t *new_hash)
{
   if (*list) {
      for (hash_t *hash = *list; hash; hash = hash->next_hash)
         if (!hash->next_hash) {
            hash->next_hash = new_hash;
            break;
         }
   }
   else
      *list = new_hash;
}

static void
start_thread(pthread_t* thread, void*(*thread_func)(void*), void* thread_func_args)
{
   pthread_attr_t attr;
   pthread_attr_init(&attr);
   pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
   pthread_create(thread, &attr, thread_func, thread_func_args);
}

static bool 
is_valid_file_ext_fmt(const char* pattern)
{
   size_t pos, len = strlen(pattern);
   char first = tolower(pattern[0]);

   for (pos = 0; pos < len; ++pos)
   {
      if ((tolower(pattern[pos]) != 'a' && tolower(pattern[pos]) != '1' && tolower(pattern[pos]) != '0') || 
           tolower(pattern[pos]) != first)
      {
         return false;
      }
   }

   return true;
}

static const char*
get_file_ext(const char* filename, const char* delim)
{
   const char* next = filename;
   const char* ext = NULL;
   while ((next = strstr(next, delim)) != NULL)
   {
      next = ext = next + 1;
   }
   return ext;
}

static const char*
get_file_base_name(const char* filename, const char* delim)
{
   const char* next = filename;
   const char* ext = NULL;
   while ((next = strstr(next, delim)) != NULL)
   {
      next = ext = next + 1;
   }

   if (ext == NULL)
   {
      return NULL;
   }

   size_t offset = (ext-1) - filename;

   char* base = xstrdup(filename);
   base[offset] = '\0';

   return base;
}

static char* 
generate_file_name(const char* unparsed_name, uint file_number)
{
   static char *digits = "0123456789";
   static char *letters = "abcdefghijklmnopqrstuvwxyz";

   const char* base_name = get_file_base_name(unparsed_name, ".");
   if (base_name == NULL)
   {
      return NULL;
   }

   const char* file_ext_fmt = get_file_ext(unparsed_name, ".");
   if (strlen(file_ext_fmt) == 0 || !is_valid_file_ext_fmt(file_ext_fmt))
   {
      return NULL;
   }
      
   size_t fmt_len = strlen(file_ext_fmt);
   size_t base_len = strlen(base_name);
   size_t len  = base_len + fmt_len + 2;
   char* file_name = (char*)malloc(len);
   snprintf(file_name, base_len + 2, "%s.", base_name);

   // In case starting with .001 
   uint64_t num = file_number + (file_ext_fmt[0] == '1' ? 1 : 0);

   for (int i = fmt_len - 1; i >= 0 ; i--)
   {
      uint64_t x;

      if ('a' == file_ext_fmt[0])
      {
         x = num % 26;
         (file_name)[base_len + 1 + i] = letters[x];
         num /= 26;
      }
      else
      {
         x = num % 10;
         (file_name)[base_len + 1 + i] = digits[x];
         num /= 10;
      }
   }

   if (num > 0)
   {
      free(file_name);
      file_name = NULL;
   }
   else
   {
      (file_name)[len - 1] = 0;
   } 
   
   return file_name;
}

static file_t*
make_file(const char *name, int number, int flags, bool part_of_set, enum VERIFICATION_TYPE verification)
{
   file_t *file = NULL;

   char *file_name = part_of_set ? generate_file_name(name, number) : strdup(name);
   if (file_name) 
   {
      file = (file_t*)malloc(sizeof(file_t));
      file->unparsed_name = strdup(name);
      file->name = file_name;
      file->part_of_set = part_of_set;
      file->number = number;
      file->flags = flags;
      file->descriptor = FILE_DESCRIPTOR_NOT_SET;
      file->offset = 0;
      file->probed = false;
      file->probed_size_in_bytes = 0;
      file->probed_size_in_sectors = 0;
      file->probed_sector_size = 0;
      file->is_device = false;
      file->is_block_device = false;
      file->bytes_processed = 0;
      file->verification = verification;
      file->next_file = NULL;
   }

   return file;
}

static void
close_file_output(output_t* output)
{
   pthread_mutex_destroy(output->buffer_queue->lock);

   file_output_t *file = output->file;
   if (file->current_file->descriptor >=0) {
      if (file->append_garbage_bytes) {
         memset(output->buffer_queue->buffers[0].data, '\0', output->buffer_size);
         ssize_t bytes_written = write(file->current_file->descriptor,
            output->buffer_queue->buffers[0].data,  output->buffer_size);
         if (bytes_written <= 0)
            report_error(0, errno,  _("corrupting %s"), quote(file->current_file->name));
      }

      if (close(file->current_file->descriptor) == 0) {
         if (output->state != FATAL_ERROR)
            // If not already in an error state, the output was completed.
            output->state = COMPLETE;
      }
      else {
         report_error(0, errno, _("closing %s"), quote(file->current_file->name));
         output->state = FATAL_ERROR;
      }
   }
}

static void
open_next_output_file(output_t* output)
{
   file_output_t *file = output->file;
   if (close(file->current_file->descriptor) == 0) {
      file->current_file->descriptor = FILE_DESCRIPTOR_NOT_SET;
      
      file_t* next_file = make_file(
         file->current_file->unparsed_name, 
         file->current_file->number + 1, 
         file->current_file->flags, 
         true,
         file->current_file->verification);
      if (next_file) {
         next_file->descriptor = open(next_file->name, next_file->flags, OUTPUT_FILE_PERMS);
         if (next_file->descriptor >= 0) {
            file->current_file = next_file;
            add_to_file_list(&file->files, next_file);
         }
         else {
            report_error(0, errno, _("opening %s"), quote(next_file->name));
            output->state = FATAL_ERROR;
         }
      }
      else {
         report_error(0, 0 , _("file extensions exhausted for %s"), file->current_file->unparsed_name);
         output->state = FATAL_ERROR;
      }
   }
   else {
      file->current_file->descriptor = FILE_DESCRIPTOR_NOT_SET;
      report_error(0, errno, _("closing %s"), quote(file->current_file->name));
      output->state = FATAL_ERROR;
   }
}

static size_t
write_bytes_to_file(output_t* output, char const *buffer, size_t bytes_to_write)
{
   size_t total_bytes_written = 0;

   file_output_t *file = output->file;
   while (total_bytes_written < bytes_to_write)
   {
      ssize_t bytes_written = write(
         file->current_file->descriptor, 
         buffer + total_bytes_written, 
         bytes_to_write - total_bytes_written);
         
      if (bytes_written < 0)
      {
         if (errno != EINTR)
         {
            report_error(0, errno, _("writing to %s"), quote(file->current_file->name));
            output->state = FATAL_ERROR;
            break;
         }
      }
      else if (bytes_written == 0)
      {
         // Some buggy drivers return 0 when one tries to write beyond
         // a device's end.  (Example: Linux 1.2.13 on /dev/fd0.)
         // Set errno to ENOSPC for a sensible diagnostic. 
         errno = ENOSPC;
         report_error(0, errno, _("writing to %s"), quote(file->current_file->name));
         output->state = FATAL_ERROR;
         break;
      }
      else
      {
         total_bytes_written += (size_t)bytes_written;
         file->current_file->bytes_processed += (size_t)total_bytes_written;
      }
   }

   return total_bytes_written;
}

static size_t
write_bytes_to_files(output_t* output, char const *buffer, size_t bytes_to_write)
{
   size_t bytes_written = 0;

   file_output_t *file = output->file;
   intmax_t bytes_left_for_file = file->max_file_size - file->current_file->bytes_processed;
   if (bytes_to_write <= bytes_left_for_file)
   {
      // Write all of the bytes in the buffer to the current file.
      bytes_written += write_bytes_to_file(output, buffer, bytes_to_write);
   }
   else
   {
      if (bytes_left_for_file > 0)
      {
         // Write the bytes that will fit in the current file. 
         bytes_written += write_bytes_to_file(output, buffer, bytes_left_for_file);
      }
      
      // Write the remaining bytes to the next file(s).
      open_next_output_file(output);
      if (output->state != FATAL_ERROR)
      {
         bytes_written += 
            write_bytes_to_files(output, buffer + bytes_written, bytes_to_write - bytes_written);
      }
   }

   return bytes_written;
}

static void
write_bytes_to_image(output_t* output, buffer_t* buffer)
{
   if (output->file->current_file->part_of_set)
      output->file->bytes_output += write_bytes_to_files(output, buffer->data, buffer->length);  
   else
      output->file->bytes_output += write_bytes_to_file(output, buffer->data, buffer->length);
}

static ssize_t
read_bytes(int file_descriptor, char *buffer, size_t bytes_to_read)
{
   for (;;) {
      ssize_t bytes_read;
      bytes_read = read(file_descriptor, buffer, bytes_to_read);
      if (!(bytes_read < 0 && errno == EINTR))
         return bytes_read;
   }
}

static void
skip_output_sectors(output_t* output)
{
   file_output_t *file = output->file;
   if (file->sectors_to_skip > 0)
   {
      uint64_t bytes_to_skip = file->sectors_to_skip * output->sector_size;
      if (bytes_to_skip <= OFF_T_MAX) 
      {
         if (lseek(file->current_file->descriptor, bytes_to_skip, SEEK_CUR) < 0)
         {
	    report_error(0, errno, _("lseek() on %s failed while skipping sectors"),
	       quote(file->current_file->name));
	    output->state = FATAL_ERROR;
         }
      }
      else
      {
         // The desired skip is not representable as an off_t, so try
         // doing the skip using read() calls.
         char* buffer = (char*)malloc(output->buffer_size);
	 while (bytes_to_skip)
	 {
	    size_t bytes_to_read =
	       bytes_to_skip >= output->buffer_size ? output->buffer_size : bytes_to_skip; 
	    ssize_t bytes_read = 
	       read_bytes(file->current_file->descriptor, buffer, bytes_to_read);
	    if (bytes_read > 0)
	    {
	       bytes_to_skip -= bytes_read;
	    }
	    else if (bytes_read == 0)
	    {
	       char message[DISPLAY_MESSAGE_LENGTH];
	       sprintf(message,  _("encountered end of file reading %s to skip sectors"),
		  quote(file->current_file->name));
	       report_error(0, 0, message); 
	       output->state = FATAL_ERROR;         
	       break;
	    }
	    else
	    {
	      report_error(0, errno, _("reading %s  while skipping sectors"),
		 quote(file->current_file->name));
	       output->state = FATAL_ERROR;
	       break;
	    }         
	 }
         free(buffer);
      }
   }
}

static void
open_file_output(output_t* output)
{
   //pthread_mutex_init(output->buffer_queue->lock, NULL);

   file_output_t *file = output->file;
   file->current_file->descriptor = 
      open(file->current_file->name, file->current_file->flags, OUTPUT_FILE_PERMS); 
   if (file->current_file->descriptor >= 0) 
   {
      output->state = OPEN;
      skip_output_sectors(output);      
   }
   else
   {
      report_error(0, errno,_("opening %s"), quote(file->current_file->name));
      output->state = FATAL_ERROR;
   }   
}

static void
disconnect_from_std_out(output_t* output)
{
   output->state = COMPLETE;
   pthread_mutex_destroy(output->buffer_queue->lock);
}

static void
connect_to_std_out(output_t* output)
{
   pthread_mutex_init(output->buffer_queue->lock, NULL);
   output->file->current_file->descriptor = STDOUT_FILENO;
   output->state = OPEN;
}

static void
get_hash_result(hash_t* hash, size_t sum_size)
{
   static char hex[] = "0123456789abcdef";

   for (size_t p = 0; p < sum_size ; p++)
   {
      hash->result[2 * p] = hex[(hash->sum[p] >> 4) & 0xf];
      hash->result[2 * p + 1] = hex[hash->sum[p] & 0xf];
   }

   hash->result[2 * sum_size] = 0;
}

static void
close_hash(output_t* output)
{
   hash_output_t * hash = output->hash;

   // Finish the total hash.
   hash->algorithm->finish(hash->total_hash->context, hash->total_hash->sum);
   get_hash_result(hash->total_hash, hash->algorithm->sum_size);

   // Finish the piecewise hash.
   if (hash->current_piece) {
      hash->algorithm->finish(hash->current_piece->context, hash->current_piece->sum);
      get_hash_result(hash->current_piece, hash->algorithm->sum_size);
   }

   // Finish the hash of the device that received the device.
   if (hash->device_hash) {
      hash->algorithm->finish(hash->device_hash->context, hash->device_hash->sum);
      get_hash_result(hash->device_hash, hash->algorithm->sum_size);
   }

   pthread_mutex_destroy(output->buffer_queue->lock);
   output->state = COMPLETE;
}

static hash_t*
make_hash(hash_algorithm_t* algorithm)
{
   hash_t* hash = (hash_t*)malloc(sizeof(hash_t));
   hash->context = malloc(algorithm->context_size);
   hash->sum = (char*)malloc(algorithm->sum_size);
   hash->result = (char*)malloc(2 * algorithm->sum_size + 1);
   hash->result[0] = 0;
   hash->bytes_hashed = 0;
   hash->next_hash = NULL;
   return hash;
}

static void
piecewise_hash_bytes(output_t* output, const char* buf, size_t buf_length)
{
   uint64_t bytes_left_for_piece = 
      output->hash->piecewise_hash_length - output->hash->current_piece->bytes_hashed;

   if (bytes_left_for_piece == 0)
   {
      output->hash->algorithm->finish(output->hash->current_piece->context,
         output->hash->current_piece->sum);
      get_hash_result(output->hash->current_piece, output->hash->algorithm->sum_size);
      output->hash->current_piece = make_hash(output->hash->algorithm);
      add_to_hash_list(&output->hash->piecewise_hash, output->hash->current_piece);
      output->hash->algorithm->init(output->hash->current_piece->context);
      bytes_left_for_piece = output->hash->piecewise_hash_length;
   }

   if (buf_length <= bytes_left_for_piece)
   {
      output->hash->algorithm->update(buf, buf_length, output->hash->current_piece->context);
      output->hash->current_piece->bytes_hashed += buf_length;
   }
   else
   {
      output->hash->algorithm->update(buf, bytes_left_for_piece,
         output->hash->current_piece->context);
      output->hash->current_piece->bytes_hashed += bytes_left_for_piece;
      piecewise_hash_bytes(output, buf + bytes_left_for_piece, buf_length - bytes_left_for_piece);
   }
}

static void
hash_bytes(output_t* output, buffer_t* buffer)
{
   hash_output_t *hash = output->hash;
   hash->algorithm->update(buffer->data, buffer->length, hash->total_hash->context);
   hash->total_hash->bytes_hashed += buffer->length;
   if (hash->current_piece)
      piecewise_hash_bytes(output, buffer->data, buffer->length);
}

static void
hash_device_bytes(output_t* output, buffer_t* buffer)
{
   hash_output_t *hash = output->hash;
   hash->algorithm->update(buffer->data, buffer->length, hash->device_hash->context);
   hash->device_hash->bytes_hashed += buffer->length;
   uint64_t bytes_remaining = hash->total_hash_length - hash->total_hash->bytes_hashed;
   if (bytes_remaining > 0) {
      if (bytes_remaining < buffer->length)
         buffer->length = bytes_remaining;
      hash->algorithm->update(buffer->data, buffer->length, hash->total_hash->context);
      hash->total_hash->bytes_hashed += buffer->length;
   }
}

static void
open_hash(output_t* output)
{
   pthread_mutex_init(output->buffer_queue->lock, NULL);

   hash_output_t *hash = output->hash;
   hash->algorithm->init(output->hash->total_hash->context);

   if (hash->current_piece != NULL)
      hash->algorithm->init(hash->current_piece->context);

   if (hash->device_hash != NULL)
      hash->algorithm->init(hash->device_hash->context);

   output->state = OPEN;
}

static bool 
wait_for_buffer(buffer_queue_t* buffer_queue)
{
   // This function is called by an output thread each time it
   // finishes consuming some input bytes furnished by an input (i.e., task) thread.

   uint buffers_used = 0;

   pthread_mutex_lock(buffer_queue->lock);
   if (buffer_queue->buffers_used == 0 && !buffer_queue->done_buffering)
   {
      pthread_cond_wait(buffer_queue->not_empty, buffer_queue->lock);
   }   

   buffers_used = buffer_queue->buffers_used;

   pthread_mutex_unlock(buffer_queue->lock);

   return buffers_used > 0;
}

static void* 
produce_output(void* arg)
{
   // This is the thread function for output threads.
   output_t* output = (output_t*)arg;
      
   size_t next_buffer = 0;
   while (wait_for_buffer(output->buffer_queue))
   {
      if (output->state == OPEN)
      {
         // Output the next buffer in the buffer queue.
         output->consume_bytes(output, &output->buffer_queue->buffers[next_buffer]);     
      }

      // Update the count of buffers in use and notify the task
      // thread that the buffer queue is not full. This will release
      // the input (i.e., task) thread if it is blocked waiting to add a
      // buffer of input bytes to this queue.
      next_buffer = (next_buffer + 1) % NUM_BUFFERS;
      pthread_mutex_lock(output->buffer_queue->lock);
      --output->buffer_queue->buffers_used;
      pthread_cond_signal(output->buffer_queue->not_full);
      pthread_mutex_unlock(output->buffer_queue->lock);
   }

   pthread_exit(NULL);
}

static void
close_file_input(input_t* input)
{
   if (input->current_file->descriptor >= 0)
   {
      if (close(input->current_file->descriptor) == 0)
      {
         if (input->state != FATAL_ERROR)
         {
            // If not already in an error state, the input was completed.
            input->state = COMPLETE;
         }
      }
      else
      {
         report_error(0, errno, _("closing %s"), quote(input->current_file->name));
         input->state = FATAL_ERROR;
      }
   }
}

static void
advance_input(input_t* input, uint64_t bytes_read)
{
   // Update the input counters.
   if (input->current_file)
   {
      input->current_file->offset += bytes_read;
      input->current_file->bytes_processed += bytes_read;
      input->current_sector += bytes_read / input->sector_size;
   }
   input->bytes_input += bytes_read;
}

static bool
advance_input_after_sector_read_error(input_t* input)
{
   advance_input(input, input->sector_size);

   // Get the actual offset of the file pointer.
   off_t offset = lseek(input->current_file->descriptor, 0, SEEK_CUR);
   
   if (offset >= 0)
   {
      if (offset != input->current_file->offset)
      {
	 // Advance the actual offset to the desired offset.
	 if (lseek(input->current_file->descriptor, input->current_file->offset - offset, SEEK_CUR) < 0)
	 {
	    report_error(0, errno, _("lseek() on %s failed, cannot advance input past read error"),
	       quote(input->current_file->name));
	    input->state = FATAL_ERROR;
	 }
      }
   }
   else
   {
      report_error(0, errno, _("lseek() on %s failed, cannot advance input past read error"),
	 quote(input->current_file->name));
      input->state = FATAL_ERROR;
   }

   return input->state != FATAL_ERROR;
}

static void
flush_grouped_read_errors(input_t* input, bool skipping)
{
   if (input->current_errno_count > 1)
   {
      report_error(0, input->current_errno,
         _("%"PRIuMAX" occurences while reading %s from sector %"PRIuMAX" to sector %"PRIuMAX" %s"), 
         input->current_errno_count,
         quote(input->current_file->name),
         input->current_errno_start_sector,
         input->current_errno_start_sector + input->current_errno_count - 1,
         skipping ? _("while skipping sectors") : "");

   }
   else if (input->current_errno_count == 1)
   {
      report_error(0, input->current_errno, _("reading %s at sector %"PRIuMAX" %s"),
         quote(input->current_file->name), input->current_errno_start_sector,
         skipping ? _("while skipping sectors") : "");
   }

   input->current_errno = 0;
   input->current_errno_count = 0;
   input->current_errno_start_sector = 0;
}

static void
report_grouped_read_error(input_t* input, uint64_t sector_number, bool skipping)
{
   if (input->current_errno_count > 0 && input->current_errno != errno)
   {
      flush_grouped_read_errors(input, skipping);
   }

   if (input->current_errno_count == 0)
   {
      input->current_errno_start_sector = sector_number;
   }

   input->current_errno = errno;
   ++input->current_errno_count;
}

static void
report_read_error(input_t* input, size_t read_size, bool skipping)
{
   if (read_size == input->sector_size)
   {
      report_error(0, errno, _("reading %s at sector %"PRIuMAX" %s"),
         quote(input->current_file->name), input->current_sector,
         skipping ? _("while skipping sectors") : "");
   }
   else
   {
      report_error(0, errno, _("reading %s in sector range %"PRIuMAX"-%"PRIuMAX" %s"),
         quote(input->current_file->name),
         input->current_sector,
         input->current_sector + read_size / input->sector_size - 1,
         skipping ? _("while skipping sectors") : "");
   }
}

static void 
recover_sectors(input_t* input, size_t bytes_to_read)
{
   pthread_mutex_lock(&reporting_lock);

   // Clear the progress display to report the recovery effort.
   fprintf(stderr, "%79s", "\r");

   size_t sectors_to_read = bytes_to_read / input->sector_size;
   size_t sectors_read = 0;   
   while (sectors_to_read > sectors_read)
   {
      // This is a slow loop, so let the user know what's going on.
      fprintf(stderr, "trying to recover sector %"PRIuMAX"", input->current_sector);

      // Obtain a pointer into the buffer corresponding to the position of the
      // current sector and attempt to read into that location.
      char* sector_buffer = input->buffer.data + sectors_read * input->sector_size; 
      ssize_t bytes_read = 
         read_bytes(input->current_file->descriptor, sector_buffer, input->sector_size);
      fprintf(stderr, "%79s", "\r");
      if (bytes_read > 0)
      {
	 flush_grouped_read_errors(input, false);
         if ((size_t)bytes_read == input->sector_size)
         {
	    // The sector was read.
	    advance_input(input, input->sector_size);
	    ++sectors_read;
         }
         else
         {
	    // Either more or fewer bytes than a sector was read. 
	    report_error(0, 0, _("reading %s, unexpected read size of %zd at sector %"PRIuMAX""), 
	       quote(input->current_file->name),
	       bytes_read, 
	       input->current_sector);
	    input->state = FATAL_ERROR;
	    break;
         }
      }
      else if (bytes_read == 0 || errno == ENOSPC)
      {
         // End of device.
         flush_grouped_read_errors(input, false);
         input->state = COMPLETE;
         break;
      }
      else 
      {
         // Cannot read the sector. Write zeros into the buffer in place of the bad sector.
         memset(sector_buffer, '\0', input->sector_size);
         ++sectors_read;
         ++input->bad_sectors;
         report_grouped_read_error(input, input->current_sector, false);
         if (!advance_input_after_sector_read_error(input))
         {
	    flush_grouped_read_errors(input, false);
            break;
         }       
      }
   } 
   input->buffer.length = sectors_read * input->sector_size;

   pthread_mutex_unlock(&reporting_lock);
}

static size_t
calculate_bytes_to_read(input_t* input)
{
   uint64_t bytes_remaining = input->bytes_to_input - input->bytes_input;   
   return bytes_remaining >= input->buffer_size ? input->buffer_size : bytes_remaining; 
}

static void
read_bytes_from_device(input_t* input)
{
   memset(input->buffer.data, '\0', input->buffer_size);
   input->buffer.length = 0;

   size_t bytes_to_read = calculate_bytes_to_read(input);
   if (bytes_to_read > 0)
   {
      ssize_t bytes_read = read_bytes(input->current_file->descriptor, input->buffer.data, bytes_to_read); 
      if (bytes_read > 0)
      {  
         // The read was successful. 
         input->buffer.length = (size_t)bytes_read;
         flush_grouped_read_errors(input, false);
         advance_input(input, (size_t)bytes_read);
      }
      else if (bytes_read == 0 || (errno == ENOSPC && bytes_to_read == input->sector_size))
      {
         // The read was an attempt to read past the end of the device. If 
         // doing sector-size reads, this is not an error, just the end of the device.
         flush_grouped_read_errors(input, false);
         input->state = COMPLETE;
      }
      else
      {
	 if (input->recover_errors)
	 {
	    recover_sectors(input, bytes_to_read);
	 }
	 else
	 {
	    report_read_error(input, bytes_to_read, false);
	    input->state = FATAL_ERROR;
	 }
      }      
   }
}

static void
read_bytes_from_file(input_t* input)
{
   memset(input->buffer.data, '\0', input->buffer_size);
   input->buffer.length = 0;

   size_t bytes_to_read = calculate_bytes_to_read(input);
   if (bytes_to_read > 0)
   {
      ssize_t bytes_read = read_bytes(input->current_file->descriptor, input->buffer.data, bytes_to_read);

      if (bytes_read > 0)
      {
	 input->buffer.length = (size_t)bytes_read;
         advance_input(input, bytes_read);
      }
      else if (bytes_read == 0)
      {
         input->state = COMPLETE;
      }
      else if (bytes_read < 0)
      {
         report_read_error(input, bytes_to_read, false);
         input->state = FATAL_ERROR;
      }
   }
}

static void
open_next_input_file(input_t* input)
{
   if (close(input->current_file->descriptor) == 0)
   {
      input->current_file->descriptor = FILE_DESCRIPTOR_NOT_SET;

      file_t* next_file = make_file(
         input->current_file->unparsed_name, 
         input->current_file->number + 1, 
         input->current_file->flags, 
         true,
         input->current_file->verification);

      if (next_file)
      {
         next_file->descriptor = open(next_file->name, next_file->flags, 0);
         if (next_file->descriptor >= 0)
         {
            // There is another file in the set.
            input->current_file = next_file;
            add_to_file_list(&input->files, next_file);
            input->state = OPEN;
         }
      }
   }
   else
   {
      input->current_file->descriptor = FILE_DESCRIPTOR_NOT_SET;
      report_error(0, errno, _("closing %s"), quote(input->current_file->name));
      input->state = FATAL_ERROR;
   }
}

static void
read_bytes_from_files(input_t* input)
{
   read_bytes_from_file(input);
   if (input->state == COMPLETE)
   {
      open_next_input_file(input);
   }
}

static void
skip_device_input_sectors(input_t* input)
{
   pthread_mutex_lock(&reporting_lock);

   // Skip a sector at a time to allow for error recovery.
   uint64_t sectors_to_skip = input->sectors_to_skip;
   do
   {
      // This is a slow loop, so let the user know what's going on.
      fprintf(stderr, "trying to skip sector %"PRIuMAX"", input->current_sector);

      ssize_t bytes_read = 
	 read_bytes(input->current_file->descriptor, input->buffer.data, input->sector_size);
      fprintf(stderr, "%79s", "\r");
      if (bytes_read > 0)
      {
         // Sucessfully skipped the sector.
	 if (input->recover_errors)
	 {
            flush_grouped_read_errors(input, true);
         }
	 advance_input(input, bytes_read);                        

         // Correct bytes input, since bytes skipped, not input
         input->bytes_input -= input->sector_size;
         input->current_file->bytes_processed -= input->sector_size;
      }
      else if (bytes_read == 0 || errno == ENOSPC)
      {
         // End of device.
	 if (input->recover_errors)
	 {
            flush_grouped_read_errors(input, true);
         }
         char message[DISPLAY_MESSAGE_LENGTH];
         sprintf(message,  _("encountered end of device reading %s to skip sectors"),
	    quote(input->current_file->name));
	 report_error(0, 0, message); 
	 input->state = FATAL_ERROR;         
	 break;
      }
      else
      {
         // Hit a bad sector.
	 if (input->recover_errors)
	 {
            // Try to jump past the bad sector.
	    report_grouped_read_error(input, input->current_sector, true);
	    if (!advance_input_after_sector_read_error(input)) 
	    {
               flush_grouped_read_errors(input, true);
	       break;
	    }      
            else
            {
	       // Correct bytes input, since bytes skipped, not input
	       input->bytes_input -= input->sector_size;
	       input->current_file->bytes_processed -= input->sector_size;
            } 
	 }
	 else
	 {
            report_read_error(input, input->sector_size, true);
	    input->state = FATAL_ERROR;
	    break;
	 }
      }         
   }
   while (--sectors_to_skip);      

   pthread_mutex_unlock(&reporting_lock);
}

static void
skip_file_input_sectors(input_t* input)
{
   uint64_t bytes_to_skip = input->sectors_to_skip * input->sector_size;
   while (bytes_to_skip)
   {
      size_t bytes_to_read =
         bytes_to_skip >= input->buffer_size ? input->buffer_size : bytes_to_skip; 
      ssize_t bytes_read = 
         read_bytes(input->current_file->descriptor, input->buffer.data, bytes_to_read);
      if (bytes_read > 0)
      {
	 advance_input(input, bytes_read);                        

         // Correct bytes input, since bytes skipped, not input
         input->bytes_input -= bytes_read;
         input->current_file->bytes_processed -= bytes_read;

         bytes_to_skip -= bytes_read;
      }
      else if (bytes_read == 0)
      {
         char message[DISPLAY_MESSAGE_LENGTH];
         sprintf(message,  _("encountered end of file reading %s to skip sectors"),
	    quote(input->current_file->name));
	 report_error(0, 0, message); 
	 input->state = FATAL_ERROR;         
	 break;
      }
      else
      {
         report_read_error(input, input->sector_size, true);
	 input->state = FATAL_ERROR;
	 break;
      }         
   }
}

static void
skip_input_sectors(input_t* input)
{
   if (input->sectors_to_skip > 0)
   {
      // Attempt to perform the skip with lseek(). If the skip is
      // too large or the lseek() call fails, resort to using read()
      // for the skip.
      uint64_t bytes_to_skip = input->sectors_to_skip * input->sector_size;
      if (bytes_to_skip <= OFF_T_MAX &&
          lseek(input->current_file->descriptor, bytes_to_skip, SEEK_CUR) >= 0)
      {
         advance_input(input, bytes_to_skip);

         // Correct bytes input, since bytes skipped, not input
         input->bytes_input -= bytes_to_skip;
         input->current_file->bytes_processed -= bytes_to_skip;
      }
      else {
         if (input->current_file->is_device)
            skip_device_input_sectors(input);
         else
            skip_file_input_sectors(input);
      }
   }
}

// Begin code copied (and modified) from md5deep helpers.c 

#ifdef __linux__

static void 
get_file_stats(file_t* file)
{
   file->probed = false;
   file->is_device = false;
   file->is_block_device = false;
   file->probed_sector_size = 0;
   file->probed_size_in_sectors= 0;
   file->probed_size_in_bytes = 0;

   struct stat file_info;
   if (fstat(file->descriptor, &file_info) == 0)
   {
      if (S_ISCHR(file_info.st_mode) || S_ISBLK(file_info.st_mode))
      {
         // The file is a character device or a block device. It is necessary to
         // use ioctl to query the OS to get the data to compute the size of the 
         // device.
         file->is_device = true;
         file->is_block_device = S_ISBLK(file_info.st_mode);
         
         uint64_t size_in_sectors = 0;
         uint64_t sector_size = 0;
         if (ioctl(file->descriptor, BLKGETSIZE, &size_in_sectors) == 0 && 
             ioctl(file->descriptor, BLKSSZGET, &sector_size) == 0)
         {
            file->probed_sector_size = sector_size;
            if (sector_size == 512)
            {
               file->probed_size_in_sectors = size_in_sectors;
            }
            else
            {
               // ioctl() reports device size in terms of 512 byte sectors, 
               // regardless of actual sector size.
               file->probed_size_in_sectors = size_in_sectors * 512 / sector_size; 
            }
            file->probed_size_in_bytes = file->probed_size_in_sectors * file->probed_sector_size;
            file->probed = true;
         }
      }
      else if (S_ISREG(file_info.st_mode))
      {
         // The file is a file (an image), so fstat returns a valid file size.   
         file->probed_size_in_bytes = file_info.st_size;
         file->probed = true;
      }
   }
}  

#elif defined (__APPLE__)

static void 
get_file_stats(file_t* file)
{
   file->probed = false;
   file->is_device = false;
   file->is_block_device = false;
   file->probed_sector_size = 0;
   file->probed_size_in_sectors= 0;
   file->probed_size_in_bytes = 0;

   struct stat file_info;
   if (fstat(file->descriptor, &file_info) == 0)
   {
      if (file_info.st_mode & S_IFBLK)
      {
         // The file is a character device or a block device. It is necessary to
         // use ioctl to query the OS to get the data to compute the size of the 
         // device.
         file->is_device = true;
         file->is_block_device = true;
         
         uint32_t sector_size = 0;
         uint64_t size_in_sectors = 0;
         if (ioctl(file->descriptor, DKIOCGETBLOCKSIZE, &sector_size) >= 0 &&
             ioctl(file->descriptor, DKIOCGETBLOCKCOUNT, &size_in_sectors) >= 0)
         {
            file->probed_size_in_sectors = (uint64_t)size_in_sectors;
            file->probed_sector_size = (uint64_t)sector_size;
            file->probed_size_in_bytes = file->probed_size_in_sectors * file->probed_sector_size;
            file->probed = true;
         }
      }
      else
      {
         // The file is a file (an image).   
         off_t start_of_file = lseek(file->descriptor, 0 , SEEK_CUR);
         off_t end_of_file = lseek(file->descriptor, 0, SEEK_END);
         if (lseek(file->descriptor, start_of_file, SEEK_SET) == 0)
         {
            file->probed_size_in_bytes = end_of_file - start_of_file;
            file->probed = true;
         }
      }
   }
}

#elif defined (__CYGWIN__) 

static void 
get_file_stats(file_t* file)
{
   file->probed = false;
   file->is_device = false;
   file->is_block_device = false;
   file->probed_sector_size = 0;
   file->probed_size_in_sectors= 0;
   file->probed_size_in_bytes = 0;

   struct stat file_info;
   if (fstat(file->descriptor, &file_info) == 0)
   {
      if (S_ISCHR(file_info.st_mode) || S_ISBLK(file_info.st_mode))
      {
         // The file is a character device or a block device. It is necessary to
         // use ioctl to query the OS to get the data to compute the size of the 
         // device.
         file->is_device = true;
         file->is_block_device = S_ISBLK(file_info.st_mode);
         
         // Use temp variables to guarantee file->size_in_sectors and file->sector_size
         // are unchanged if the ioctl calls fail.
         uint64_t size_in_sectors = 0;
         uint64_t sector_size = 0;
         if (ioctl(file->descriptor, BLKGETSIZE, &size_in_sectors) == 0 && 
             ioctl(file->descriptor, BLKSSZGET, &sector_size) == 0)
         {
            file->probed_size_in_sectors = size_in_sectors;
            file->probed_sector_size = sector_size;
            file->probed_size_in_bytes = file->probed_size_in_sectors * file->probed_sector_size;
            file->probed = true;
         }
      }
      else if (S_ISREG(file_info.st_mode))
      {
         // The file is a file (an image), so fstat returns a valid file size.   
         file->probed_size_in_bytes = file_info.st_size;
         file->probed = true;
      }
   }
}

#endif // ifdef __LINUX__

// End code copied (and modified) from md5deep helpers.c
   
static bool 
probe_file(file_t* file)
{
   if (!file->probed) {
      get_file_stats(file);
      if (file->probed && file->part_of_set) {
	 // Generate the set of potential file names and attempt to
	 // open the set of files. Stop when file extensions are exhausted 
	 // or the next file does not exist. Note that there is an assumption
	 // here that the set of files was generated by this program, so
	 // exhaustion of file extensions should not be an issue.   
	 file_t next_file; 
	 next_file.number = file->number;
         next_file.probed = false;
	 next_file.probed_size_in_bytes = 0;
	 next_file.probed_sector_size = 0;
	 next_file.name = generate_file_name(file->unparsed_name, ++next_file.number); 
	 while (next_file.name) {
	    next_file.descriptor = open(next_file.name, O_RDONLY, 0);
	    if (next_file.descriptor >= 0) {
	       // This is another file in the set, get its size.
	       get_file_stats(&next_file);
	       if (next_file.probed)
		  file->probed_size_in_bytes += next_file.probed_size_in_bytes;
	       else {
		  report_error(0, 0, _("probe of %s failed"), quote(next_file.name));
		  file->probed = false;
	       }

	       if (close(next_file.descriptor) != 0) {
		  report_error(0, errno, _("closing %s after size probe"), quote(next_file.name));
		  file->probed = false;
	       }

	       free(next_file.name);
               if (!file->probed)
                  break;
	    }
	    else
	    {
	       // The next file does not exist, which is not an error (see comment above).
	       free(next_file.name);
	       break;
	    }

	    next_file.name = generate_file_name(file->unparsed_name, ++next_file.number); 
	 }
      }
   }
   return file->probed;
}

static void
open_file_input(input_t* input)
{
   input->current_file->descriptor = open(input->current_file->name, input->current_file->flags, 0); 
   if (input->current_file->descriptor >= 0) {
      if (probe_file(input->current_file)) {
	 input->state = OPEN;            
         
         // If bytes to input is not pre-determined, calculate bytes to input
         // from input size.
         if (input->bytes_to_input == 0) {
	    input->bytes_to_input = input->current_file->probed_size_in_bytes; 
	    if (input->max_sectors_to_input != INFINITE_SECTORS) {
	       uint64_t max_bytes_to_input = input->max_sectors_to_input * input->sector_size;
	       if (max_bytes_to_input < input->bytes_to_input)
	          input->bytes_to_input = max_bytes_to_input;
	    }
         }

	 skip_input_sectors(input);      
      }
      else {
	 report_error(0, errno, _("probing %s for bytes to input"), quote(input->current_file->name)); 
	 input->state = FATAL_ERROR;
      }
   }
   else {
      report_error(0, errno, _("opening %s"), quote(input->current_file->name)); 
      input->state = FATAL_ERROR;
   }
}

static void
disconnect_from_std_in(input_t* input)
{
   input->state = COMPLETE;
   input->current_file->descriptor = FILE_DESCRIPTOR_NOT_SET; 
}

static void
connect_to_std_in(input_t* input)
{
   input->current_file->descriptor = STDIN_FILENO; 
   input->bytes_to_input = INFINITE_BYTES;
   input->state = OPEN;
}

static void
close_pattern_input(input_t* input)
{
   input->state = COMPLETE;
}

static void
read_bytes_from_pattern(input_t* input)
{
   // The pattern is already loaded into the buffer, so only bookkeeping is required.
   size_t bytes_read = calculate_bytes_to_read(input);
   input->buffer.length = bytes_read;
   advance_input(input, bytes_read);
}

static void
open_pattern_input(input_t* input)
{
   // Load the pattern into the input buffer.
   for (uint64_t i = 0; i < input->buffer_size; ++i)
   {
      input->buffer.data[i] = input->pattern[i % input->pattern_length];
   }      
   input->buffer.length = input->buffer_size;   

   input->bytes_to_input = input->sector_size * input->max_sectors_to_input;
   input->state = OPEN;
}

static void 
set_exit_code(task_t* task)
{
   pthread_mutex_lock(task->signaling_lock);
   task->completed = true;
   if (task->aborted)
   {
      task->exit_code = DC3DD_EXIT_ABORTED;
   }

   if (task->exit_code != DC3DD_EXIT_ABORTED)
   {
      task->exit_code = DC3DD_EXIT_COMPLETED;

      if (task->input->state != COMPLETE)
      {
         task->exit_code = DC3DD_EXIT_FAILED;
      }
      else
      {
         output_t* output = task->outputs;
         while (output)
         {
            if (output->state != COMPLETE)
            {
               task->exit_code = DC3DD_EXIT_FAILED;
               break;
            }
            output = output->next_output;
         }
      }
   }
   pthread_mutex_unlock(task->signaling_lock);
}

static void
close_IO(task_t* task)
{
   task->input->close(task->input);
   
   output_t* output = task->outputs;
   while (output)
   {
      output->close(output);
      output = output->next_output;
   }      
}

static void
wait_for_output_threads(task_t* task)
{
   output_t* output = task->outputs;
   while (output)
   {
      // Set the done buffering flag on the output buffer queue and
      // signal not empty to release the output thread, since it may be 
      // blocked waiting for the next buffer to be copied into the
      // output buffer queue.
      pthread_mutex_lock(output->buffer_queue->lock);
      output->buffer_queue->done_buffering = true;
      pthread_cond_signal(output->buffer_queue->not_empty);
      pthread_mutex_unlock(output->buffer_queue->lock);

      pthread_join(output->thread, NULL);
      output = output->next_output;
   }   
}

static void
produce_bytes(task_t* task)
{
   // Produce an input buffer and copy it to each output buffer queue.
   input_t *input = task->input;
   input->produce_bytes(input); 
   if (input->buffer.length > 0) {
      for (output_t *output = task->outputs; output; output = output->next_output) {
         // Wait for an empty buffer in the buffer queue for this
         // output.
         buffer_queue_t *buffer_queue = output->buffer_queue;
         pthread_mutex_lock(buffer_queue->lock);
         if (buffer_queue->buffers_used == buffer_queue->number_of_buffers)
            pthread_cond_wait(buffer_queue->not_full, buffer_queue->lock);
         pthread_mutex_unlock(buffer_queue->lock);

         // Copy the input buffer into the buffer queue. 
         memcpy(buffer_queue->buffers[buffer_queue->next_available_buffer].data,
            input->buffer.data, input->buffer.length);
         buffer_queue->buffers[buffer_queue->next_available_buffer].length = input->buffer.length;

         // Notify the output thread that another buffer is available.
         // This will release the output thread if it is blocked waiting
         // for bytes to output.
         pthread_mutex_lock(buffer_queue->lock);
         buffer_queue->next_available_buffer = 
            (buffer_queue->next_available_buffer + 1) % buffer_queue->number_of_buffers;
         ++buffer_queue->buffers_used;
         pthread_cond_signal(buffer_queue->not_empty);
         pthread_mutex_unlock(buffer_queue->lock);
      }
   }
}

static bool
is_task_completed(task_t* task)
{
   pthread_mutex_lock(task->signaling_lock);
   
   // Check for task killed.
   task->completed = task->aborted;
   
   // Check for bytes to input reached.
   if (!task->completed && task->input->bytes_to_input != INFINITE_BYTES)
   {
      task->completed = task->input->bytes_to_input - task->input->bytes_input <= 0;
   }

   // Check for input completed or in an error state.
   if (!task->completed)
   {
      task->completed = task->input->state == COMPLETE || task->input->state == FATAL_ERROR;
   }

   // Check for an output in  an error state.
   if (!task->completed)
   {
      output_t* output = task->outputs;
      while (output)
      {
         if (output->state == FATAL_ERROR)
         {
            task->completed = true;
            break;
         }
         output = output->next_output;
      }
   }

   pthread_mutex_unlock(task->signaling_lock);
   
   return task->completed;
}

static void
start_output_threads(task_t* task)
{
   output_t* output = task->outputs;
   while (output)
   {
      start_thread(&output->thread, produce_output, output);
      output = output->next_output;
   }
   
   usleep(10*1000);
}

static bool
open_IO(task_t* task)
{
   task->input->open(task->input);
   if (task->input->state == OPEN)
   {      
      output_t* output = task->outputs;
      while (output)
      {
         output->open(output);
         if (output->state != OPEN)
         {
            close_IO(task);
            return false;
         }
         output = output->next_output;
      }   
   }
   else
   {
      return false;
   }
   
   return true;
}

static void* 
execute_task(void* arg) {
   task_t* task = (task_t*)arg;

   if (task->verification_target) { 
      if (task->verification_target->verification == DEVICE_PARTIAL)
      // If this task is a verification of only the bytes dc3dd wrote to a
      // device, limit the size of the input to the number of bytes written
      // to the verification target during imaging.
      task->input->bytes_to_input = task->verification_target->bytes_output;

      if (task->verification_target->verification == DEVICE_FULL)
      // If this task is a verification of both the bytes dc3dd wrote to a
      // device and the entire device, limit the total hash(es) to the number of
      // bytes written to the verification target during imaging.
      for (output_t *output = task->outputs; output; output = output->next_output) {
         if (output->hash)
            output->hash->total_hash_length = task->verification_target->bytes_output;
      }
   }

   if (open_IO(task)) {
      start_output_threads(task);
      while (!is_task_completed(task)) 
         produce_bytes(task);
      wait_for_output_threads(task);   
      close_IO(task);
   }
   set_exit_code(task);
   pthread_exit(NULL);
}

static void
abort_job(job_t *job) {
   for (task_t *task = job->tasks; task; task = task->next_task) {
      pthread_mutex_lock(task->signaling_lock);
      task->aborted = true;
      pthread_mutex_unlock(task->signaling_lock);         
   }
}

static bool 
job_is_active(job_t* job) {
   bool is_active = false;
   
   for (task_t *task = job->tasks; task; task = task->next_task) {
      pthread_mutex_lock(task->signaling_lock);
      is_active = !task->completed && !task->aborted;
      pthread_mutex_unlock(task->signaling_lock);               
   
      if (is_active)
         break;
   }
   
   return is_active;
}

static void*
monitor_job(void *arg)
{
   // This is the thread function for a job monitoring thread.
   // The thread detects when the job is completed and emits progress reports.
   job_t* job = (job_t*)arg;

   struct timeval time_now;
   struct timespec next_progress_check_time;
   while (true)
   {
      // Compute the absolute time of next job progress check.
      gettimeofday(&time_now, NULL);
      next_progress_check_time.tv_sec = time_now.tv_sec + job->progress_interval_in_ms / 1000;
      next_progress_check_time.tv_nsec = 
         time_now.tv_usec * 1000 + (job->progress_interval_in_ms % 1000) * 1000000;
      if (next_progress_check_time.tv_nsec >= 1000000000)
      {
         next_progress_check_time.tv_nsec -= 1000000000;
         ++next_progress_check_time.tv_sec;
      }
      
      // Wait until either the signal handling thread receives an interrupt or
      // it's time for another progress check and report. 
      pthread_mutex_lock(&signaling_lock);
      if (pthread_cond_timedwait(interrupted, &signaling_lock, &next_progress_check_time) == ETIMEDOUT)
      {
         pthread_mutex_unlock(&signaling_lock);      
         job->report_progress(job, false);
         if (!job_is_active(job))
         {
            break;
         }
      }
      else
      {
         abort_job(job);
         break;
      }
   }

   pthread_exit(NULL);   
}

static void*
await_interrupt_signal(void* arg)
{
   // This is the thread function for a thread that merely waits for an
   // interrupt signal.
   arg = arg; // Avoid a warning from the compiler when compiling with -Wextra, -Wall flags.

   // Wait for an interrupt signal.
   int sig = 0;
   sigset_t set;
   sigemptyset(&set);
   sigaddset(&set, SIGINT);
   sigwait(&set, &sig);
   
   pthread_mutex_lock(&signaling_lock);
   pthread_cond_signal(interrupted);
   pthread_mutex_unlock(&signaling_lock);

   pthread_exit(NULL);
}

static int
execute_job(job_t* job)
{
   // Start a thread for each task in the job, plus a progress
   // monitoring thread.
   task_t* task = job->tasks;
   while (task)
   {
      pthread_mutex_init(task->signaling_lock, NULL);
      start_thread(&task->thread, execute_task, task);
      task = task->next_task;
   }
   start_thread(&job->monitor_thread, monitor_job, job);

   // Now the main thread blocks until the monitoring and
   // task threads finish.
   pthread_join(job->monitor_thread, NULL);
   task = job->tasks;
   while (task)
   {
      pthread_join(task->thread, NULL);
      pthread_mutex_destroy(task->signaling_lock);
      task = task->next_task;
   }

   // Assign an exit code by rolling up the task results.
   job->exit_code = DC3DD_EXIT_COMPLETED;
   task = job->tasks;
   while (task)
   {
      if (task->exit_code != DC3DD_EXIT_COMPLETED)
      {
         job->exit_code = task->exit_code;
         break;
      }
      task = task->next_task;
   }
   return job->exit_code;
}

static int
execute_jobs(job_t* jobs)
{
   // Block interrupt (SIGINT) signals so that threads created after this point, 
   // INCLUDING the interrupt signal handling thread, will also have interrupt signals blocked. 
   // The signal handling thread will get signals from the sigwait() function, 
   // instead of directly from the operating system.  
   sigset_t set;
   sigemptyset(&set);
   sigaddset(&set, SIGINT);
   pthread_sigmask(SIG_BLOCK, &set, 0);

   // Set up synchronization for signal handling and kick off the signal handling thread.
   pthread_mutex_init(&signaling_lock, NULL);      
   interrupted = (pthread_cond_t*)malloc(sizeof(pthread_cond_t));
   pthread_cond_init(interrupted, NULL);
   pthread_t signal_handling_thread;
   start_thread(&signal_handling_thread, await_interrupt_signal, NULL);
   
   int exit_code = DC3DD_EXIT_CODE_NOT_SET;      
   job_t* job = jobs;
   while (job)
   {
      exit_code = execute_job(job);
      if (exit_code != DC3DD_EXIT_COMPLETED)
      {
         break;
      }
      job = job->next_job;
   } 

   // Shut down the signal handling thread and tear down synchronization.      
   pthread_cancel(signal_handling_thread);
   pthread_mutex_destroy(&signaling_lock);
   
   return exit_code;
}

static job_t* 
make_job(task_t* tasks, void (*report_progress)(job_t*, bool))
{
   job_t* job = (job_t*)malloc(sizeof(job_t)); 
   job->tasks = tasks;
   job->progress_interval_in_ms = JOB_PROGRESS_INTERVAL_MILLISECS;
   job->report_progress = report_progress;
   job->exit_code = DC3DD_EXIT_CODE_NOT_SET;
   job->next_job = NULL;
   return job;
}

static task_t*
make_task(input_t *input, output_t *outputs, file_output_t *verification_target)
{
   task_t *task = (task_t*)malloc(sizeof(task_t)); 
   task->signaling_lock = (pthread_mutex_t*)malloc(sizeof(pthread_mutex_t));
   task->input = input;   
   task->outputs = outputs;
   task->verification_target = verification_target;
   task->completed = false;
   task->aborted = false;
   task->exit_code = DC3DD_EXIT_CODE_NOT_SET;
   task->next_task = NULL;   
   return task;
}

static buffer_queue_t*
make_buffer_queue(size_t size_in_bytes, size_t number_of_buffers)
{
   buffer_queue_t* buffer_queue = (buffer_queue_t*)malloc(sizeof(buffer_queue_t));
   buffer_queue->buffers = (buffer_t*)malloc(number_of_buffers * sizeof(buffer_t));
   for (size_t i = 0; i < number_of_buffers; ++i)
   {
      buffer_queue->buffers[i].length = 0;
      buffer_queue->buffers[i].data = (char*)malloc(size_in_bytes * sizeof(char));
   }
   buffer_queue->number_of_buffers = number_of_buffers;
   buffer_queue->buffers_used = 0;
   buffer_queue->next_available_buffer = 0;

   buffer_queue->lock = (pthread_mutex_t*)malloc(sizeof(pthread_mutex_t));
   pthread_mutex_init(buffer_queue->lock, NULL);

   buffer_queue->not_empty = (pthread_cond_t*)malloc(sizeof(pthread_cond_t));
   pthread_cond_init(buffer_queue->not_empty, NULL);

   buffer_queue->not_full = (pthread_cond_t*)malloc(sizeof(pthread_cond_t));
   pthread_cond_init(buffer_queue->not_full,  NULL);

   buffer_queue->done_buffering = false;

   return buffer_queue;
}

static output_t*
make_output(settings_t* settings)
{
   output_t* output = (output_t*)malloc(sizeof(output_t));
   output->state = PENDING;
   output->sector_size = settings->sector_size;
   output->buffer_size = settings->buffer_size;
   output->buffer_queue = make_buffer_queue(output->buffer_size, NUM_BUFFERS);
   output->hash = NULL;
   output->file = NULL;
   output->open = NULL;
   output->consume_bytes = NULL;
   output->close = NULL;
   output->next_output = NULL;
   return output;
}

static output_t*
make_file_output(settings_t* settings, file_t* file, hash_output_t* expected_hashes)
{
   if (settings->append_output || settings->output_sectors_to_skip)
      file->flags |= O_APPEND;
   else
      file->flags |= (O_CREAT | O_TRUNC);

   // Construct the "base part."
   output_t* output = make_output(settings);

   // Select the open, consume bytes, and close functions based on file type.
   output->consume_bytes = write_bytes_to_image;
   if (STREQ(file->name, "stdout")) {
      output->open = connect_to_std_out;
      output->close = disconnect_from_std_out;
   } else {
      output->open = open_file_output;
      output->close = close_file_output;
   }

   // Construct the "derived part."
   output->file = (file_output_t*)malloc(sizeof(file_output_t));
   output->file->current_file = file;
   output->file->files = file->part_of_set ? file : NULL;
   output->file->max_file_size = settings->max_output_file_size;
   output->file->sectors_to_skip = settings->output_sectors_to_skip;
   output->file->bytes_output = 0;
   output->file->verification = file->verification;
   output->file->append_garbage_bytes = settings->corrupt_output;
   output->file->expected_hashes = expected_hashes;
   output->file->actual_hashes = NULL;

   return output;
}

static output_t*
make_hash_output(settings_t *settings, hash_algorithm_t *algorithm, enum VERIFICATION_TYPE verification)
{
   output_t* output = make_output(settings);
   output->hash = (hash_output_t*)malloc(sizeof(hash_output_t));
   output->hash->algorithm = algorithm;
   output->hash->total_hash = make_hash(algorithm);
   output->hash->total_hash_length = INFINITE_BYTES;
   output->hash->current_piece = NULL;
   output->hash->piecewise_hash = NULL;
   output->hash->piecewise_hash_length = 0; 
   output->hash->device_hash = verification == DEVICE_FULL ? make_hash(algorithm) : NULL;
   output->hash->next = NULL;
   output->open = open_hash; 
   output->consume_bytes = verification == DEVICE_FULL ? hash_device_bytes : hash_bytes;
   output->close = close_hash;

   if (settings->splitting_output && settings->verifying_output) {
      output->hash->current_piece = make_hash(algorithm);
      output->hash->piecewise_hash = output->hash->current_piece; 
      output->hash->piecewise_hash_length = settings->max_output_file_size;
   }
  
   return output;
}

static output_t*
make_hash_outputs(settings_t *settings, enum VERIFICATION_TYPE verification)
{
   output_t *hash_outputs = NULL;

   for (uint8_t i = 0 ; i < NUM_HASHES ; ++i) {
      if (hash_algorithms[i].active) {
         add_to_output_list(&hash_outputs, make_hash_output(settings, &hash_algorithms[i], verification));
      }
   }
   
   return hash_outputs;
}

static void
make_hash_outputs_list(output_t *outputs, hash_output_t **hash_outputs)
{
   for (output_t *output = outputs; output; output = output->next_output) {
      if (output->hash)
         add_to_hash_output_list(hash_outputs, output->hash);
   }
}

static input_t*
make_input(settings_t* settings)
{
   input_t* input = (input_t*)malloc(sizeof(input_t));
   input->state =  PENDING;
   input->sector_size = settings->sector_size;
   input->max_sectors_to_input = settings->max_sectors_to_input; 
   input->bytes_to_input = 0;
   input->bytes_input = 0;   
   input->current_file = NULL;
   input->files = NULL;
   input->sectors_to_skip = settings->input_sectors_to_skip;   
   input->current_sector = 0; 
   input->recover_errors = settings->recover_errors;
   input->current_errno = 0;
   input->current_errno_count = 0;
   input->current_errno_start_sector = 0;
   input->bad_sectors = 0;
   input->pattern_string = NULL;
   input->pattern = NULL;
   input->pattern_length = 0;
   input->current_file = NULL;
   input->files = NULL;
   
   // The input buffer needs to be aligned if doing direct I/O
   // There is no harm in aligning it in either case.
   input->buffer_size = settings->buffer_size;
   input->buffer.data =
      (char*)malloc((input->buffer_size) + 2 * getpagesize() - 1);
   input->buffer.data = (char*)ptr_align(input->buffer.data, getpagesize());
   input->buffer.length = 0;
  
   // Select the open, produce_bytes, and close functions based on input type.
   if (settings->input_file) {
      input->current_file = settings->input_file;
      if (input->current_file->part_of_set)
         input->files = input->current_file;

      if (STREQ(input->current_file->name, "stdin")) {
	 input->open = connect_to_std_in;
	 input->produce_bytes = read_bytes_from_file;
	 input->close = disconnect_from_std_in;
      }
      else {
         input->open = open_file_input;

         // This ASSUMES that probe_file() was called on settings->input_file
         // before calling this function.
	 if (input->current_file->is_device) {
	    if (input->recover_errors)
	       input->current_file->flags |= O_DIRECT;
	    input->produce_bytes = read_bytes_from_device;
	 }
	 else if (input->current_file->part_of_set)
	    input->produce_bytes = read_bytes_from_files;
	 else
	    input->produce_bytes = read_bytes_from_file;

         input->close = close_file_input;
      }
   }
   else {
      input->pattern_string = strdup(settings->input_pattern_string);
      input->pattern = strdup(settings->input_pattern);
      input->pattern_length = settings->input_pattern_length;
      input->open = open_pattern_input;
      input->produce_bytes = read_bytes_from_pattern;
      input->close = close_pattern_input; 
   }
 
   return input;
}

static void
add_verification_job(job_t* job, settings_t* settings)
{  
   // An imaging job consists of a single task.
   task_t* imaging_task = job->tasks;

   // Make a verification task for each output to be verified.
   task_t* verification_tasks = NULL;
   for (output_t* output = imaging_task->outputs; output; output = output->next_output) {
      if (output->file && output->file->verification != NONE) {
         // Make an input file corresponding to the output file
         // and swap it into the already initialized and validated settings.
         settings->input_file = make_file(output->file->current_file->unparsed_name,
            0, O_RDONLY, output->file->current_file->part_of_set, output->file->verification);
	 input_t* input = make_input(settings);   

         // If output sectors were skipped, those sectors need to be skipped
         // for verification, too.
         if (output->file->sectors_to_skip > 0)
	   input->sectors_to_skip = output->file->sectors_to_skip;
	 else
	   input->sectors_to_skip = 0;

         // Prepare the output hashes and cache a pointer to the list
         // for later comparision with the list of input hashes cached
         // in the output when the imaging job was created. 
         output_t *output_hashes = make_hash_outputs(settings, output->file->verification);
         make_hash_outputs_list(output_hashes, &output->file->actual_hashes);    

         task_t* verification_task = make_task(input, output_hashes, output->file);
	 add_to_task_list(&verification_tasks, verification_task);
      }
   }
 
   job->next_job = make_job(verification_tasks, report_verification_progress);
}

static job_t*
make_imaging_job(settings_t* settings)
{
   input_t* input = make_input(settings);   

   output_t* input_hashes = make_hash_outputs(settings, NONE);
   hash_output_t* expected_hashes = NULL;
   make_hash_outputs_list(input_hashes, &expected_hashes);

   // Make the file outputs.
   output_t* outputs = NULL;
   if (settings->wipe_target)
   {
      add_to_output_list(&outputs, make_file_output(settings, settings->wipe_target, expected_hashes));
   } 
   else
   {
      file_t* file = settings->output_files;
      while (file)
      {
	 output_t* output = make_file_output(settings, file, expected_hashes);
	 add_to_output_list(&outputs, output);
	 file = file->next_file;
	 
	 // Unlink the file for tidiness, and so that the next_file pointer
	 // can be used to make a list of files (if splitting the output). 
	 output->file->current_file->next_file = NULL;
      }
   }

   // Append the hash outputs for the input hashes to the file outputs. 
   add_to_output_list(&outputs, input_hashes);

   task_t* task = make_task(input, outputs, NULL);
   return make_job(task, report_imaging_progress);
}

static job_t*
make_jobs(settings_t* settings)
{
   job_t* job = make_imaging_job(settings);
   if (settings->verifying_output)
   {
      add_verification_job(job, settings);
   }
   return job;
}
  
#if USE_HDPARM
#ifdef __linux__

static void 
check_device_for_hpa_dco(file_t* device)
{
   if (device->type == DEVICE)
   {
      device->descriptor = open(device->name, O_RDONLY, device->perms); 
      if (device->descriptor >= 0)
      {   
         report(_("checking for HPA/DCO: "), JOB_LOGS);
         
         int err = 0;
         __u16 *id = (void *)-1;
         __u16 *dci = (void *)-1;

         dci = get_dci_data(fd, dci);
         __u64 maximum_lba = 0;
         if (dci) 
         {
            maximum_lba = get_dci_maximum_lba(dci);
         }

         __u64 visible, native;
         id = get_identify_data(fd, id);
         if (id) 
         {
            visible = get_lba_capacity(id);
            native  = do_get_native_max_sectors_to_input(fd, id);
            if (!native) 
            {
               err = errno;
            }
         }

         if (!dci || !id || !native)
         {
            report(_("device doesn't support ATA commands\n"), JOB_LOGS);   
            return;
         }

         if (id)
         {
            bool hpa = false;
            bool dco = false;

            if (visible != native)
            {
               hpa = true;
            }

            if (maximum_lba != native)
            {
               dco = true;
            }

            if (hpa && dco)
            {
               report(_("HPA and DCO found\n"), JOB_LOGS);   
            }
            else if (hpa)
            {
               report(_("HPA found\n"), JOB_LOGS);   
            }
            else if (dco)
            {
               report(_("DCO found\n"), JOB_LOGS);   
            }
            else 
            {
               report(_("none\n"), JOB_LOGS);   
            }

            char limits[DISPLAY_MESSAGE_LENGTH];
            
            if (hpa)
            {
               sprintf(limits, _("HPA limit: %11llu sectors\n"));
               report(limits, JOB_LOGS);         
            }

            if (dco)
            {
               sprintf(limits, _("DCO limit: %11llu sectors\n"));
               report(limits, JOB_LOGS);         
            }

            sprintf(limits, _("full size: %11llu sectors\n"), maximum_lba);
            report(limits), JOB_LOGS;         
         }

         if (close(device->descriptor) == 0)
         {
            device->descriptor = FILE_DESCRIPTOR_NOT_SET;      
         }
         else
         {
            report_error(DC3DD_EXIT_ABORTED, errno, _("closing %s after HPA/DCO check"), quote(device->name));
         }      
      }
   }
}

#endif // #ifdef __linux__
#endif // #if USE_HDPARM

/* DM ADDED to clean screen print */
/****************************************************************************
*  FUNCTION:  char *format_LL( long long  )
*  long long (64 bit) nbr: number to format into a string    
*  return:  a pointer to a string containing the reformatted number.
* PURPOSE:   the function takes a 64 bit unsigned integer and formats it 
*            with commas depending upon the fmat parameter
*            and it returns a pointer to a string.
***************************************************************************/
char *format_LL( long long uLL )
{
   static   char  *string=NULL;
   int x, y, z, pos=0;
   if( string==NULL )
      string = (char *)malloc( sizeof(char *)*66);
   for( x=0; x<66; x++)
       string[x]=0;
   y=64; 
   pos=0;
   if( uLL==0 )   /* special case */
      {
         string[y--]='0';
         return(&string[y+1]); 
      }
   while( uLL >= 10 )
      {
         z= (uLL % 10);
         string[y--]= '0'+z;
         pos++;
         if( !(pos%3))
            {
               string[y--]=',';
               pos=0;
            }
         uLL = uLL/10;           
      }
   if(uLL)
      string[y--]= '0'+uLL;
   return(&string[y+1]);      
}
/* DM ADDED to clean screen print */


static void
report_device_size(file_t* device)
{
   char stats[DISPLAY_MESSAGE_LENGTH];
   //sprintf(stats, _("device size: %"PRIuMAX" sectors (probed)\n"), device->probed_size_in_sectors);

   sprintf(stats, _("device size: %"PRIuMAX" sectors (probed),   %14s bytes\n"), device->probed_size_in_sectors, 
                          format_LL( (device->probed_size_in_sectors * device->probed_sector_size) ) );
   report(stats, JOB_LOGS);   
   
   #if USE_HDPARM
   #ifdef __linux__
   if (device->is_block_device)
   {
      device->descriptor = open(device->name, O_RDONLY, device->perms); 
      if (device->descriptor >= 0)
      {   
	 check_device_for_hpa_dco(device->descriptor);
	 if (close(device->descriptor) == 0)
	 {
	    device->descriptor = FILE_DESCRIPTOR_NOT_SET;      
	 }
	 else
	 {
	    report_error(DC3DD_EXIT_ABORTED, errno, _("closing %s after hpa/dco check"), quote(device->name));
	 }      
      }
   }
   #endif
   #endif         
}

static void
report_input_size(settings_t *settings)
{
   if (settings->wipe_target)
      report_device_size(settings->wipe_target); 
   else if (settings->input_file && settings->input_file->is_device)
      report_device_size(settings->input_file);
   
   char message[DISPLAY_MESSAGE_LENGTH];
   sprintf(message, "sector size: %zd bytes (%s)\n", settings->sector_size, settings->sector_size_source);
   report(message, JOB_LOGS);
   flush_logs();
}

static void 
activate_hash(const char* algorithm_name)
{
   uint8_t i = 0;

   // Command line settings override build time settings, so deactivate
   // all hashing algorithms activated by build settings.
   static bool predefined_hashes_cleared = false;
   if (!predefined_hashes_cleared)
   {
      for (i = 0; i < NUM_HASHES; ++i)
      {
         hash_algorithms[i].active = false;
      }
      
      predefined_hashes_cleared = true;   
   }

   for (i = 0; i < NUM_HASHES; ++i)
   {
      if (STREQ(hash_algorithms[i].name, algorithm_name))
      {
         if (!hash_algorithms[i].active)
         {
            hash_algorithms[i].active = true;
         }
         else
         {
            report_error(DC3DD_EXIT_ABORTED,0,_("hash=%s specified more than once"), quote(algorithm_name));
         }
         break;
      }
   }

   // Note the early out for command line errors since evidence should not
   // be handled any more than necessary, and glossing over a malformed
   // command line is therefore undesirable - the user's choices need to be
   // exactly specified before a run is undertaken.
   if (i == NUM_HASHES)
   {
      report_error(DC3DD_EXIT_ABORTED,0,_("unknown hash algorithm %s"), quote(algorithm_name));
   }
}

static void
probe_file_for_validation(file_t* file)
{
   file->descriptor = open(file->name, O_RDONLY, 0); 
   if (file->descriptor >= 0) {
      if (probe_file(file)) {
         if (close(file->descriptor) == 0) {
            file->descriptor = FILE_DESCRIPTOR_NOT_SET;      
         }
         else
         {
            report_error(DC3DD_EXIT_ABORTED, errno, _("closing %s after validation probe"), quote(file->name));
         }      
      }
      else
      {
         close(file->descriptor);
         report_error(DC3DD_EXIT_ABORTED, 0, _("validation probe of %s failed"), quote(file->name));
      }
   }
   else
   {
      report_error(DC3DD_EXIT_ABORTED, errno, _("opening %s for validation probe"), quote(file->name));
   }
}

static void
add_wipe_target(settings_t* settings, const char* device_name, enum VERIFICATION_TYPE verification)
{
   // Note the early outs for command line errors since evidence should not
   // be handled any more than necessary, and glossing over a malformed
   // command line is therefore undesirable - the user's choices need to be
   // exactly specified before a run is undertaken.

   if (settings->wipe_target)
      report_error(DC3DD_EXIT_ABORTED, 0, _("cannot specify wipe= or hwipe= more than once"));      

   if (settings->output_files)
      report_error(DC3DD_EXIT_ABORTED, 0, _("cannot combine wipe= or hwipe= and of=, hof=, ofs= or hofs="));
  
   settings->wipe_target = make_file(device_name, 0, O_WRONLY, false, verification);
   DC3DD_ASSERT(settings->wipe_target != NULL);
 
   // Make sure the wipe target is valid.
   probe_file_for_validation(settings->wipe_target);
   if (!settings->wipe_target->is_device)
      report_error(DC3DD_EXIT_ABORTED, errno, _("%s not recognized as a device, cannot wipe"),
	quote(settings->wipe_target->name));
   if (settings->wipe_target->probed_size_in_bytes <= 0)
      report_error(DC3DD_EXIT_ABORTED, errno, _("%s size probe failed, cannot wipe"),
         quote(settings->wipe_target->name));

   if (verification != NONE)
      settings->verifying_output = true;
}

static void 
add_output_file(settings_t *settings, const char *file_name, bool part_of_set,
   enum VERIFICATION_TYPE verification)
{
   if (verification != NONE) {
      if (STREQ(file_name, "/dev/null"))
         report_error(DC3DD_EXIT_ABORTED, 0, 
         _("cannot output to /dev/null if using hof=, hofs=, or fhod="));
      else
         settings->verifying_output = true;
   }

   if (part_of_set)
      settings->splitting_output = true;

   file_t* file = make_file(file_name, 0, O_WRONLY, part_of_set, verification);
   
   //This portion of code checks if output destination exists. If it does exist
   // it will then probe it to see if it is a file or device. Next, it changes
   // the verification type from standard to partial if it is a device.
   //It will also error out if the user selects partial or full verification
   // with a file set as the output.
   if (file) {
      file->descriptor = open(file->name, O_RDONLY, 0); //attempt to open destination file
	 if (file->descriptor >= 0 && !STREQ(file_name, "/dev/null")) { //any other outputs to ignore?JKL
	    //destination exists - check if destination is a device or file
	    // and get details
	    close(file->descriptor);
            probe_file_for_validation(file);
	 }
      if (verification == STANDARD && file->is_device) {
	 //change hashing behavior - if user selects standard hashing for a
	 // device, default to partial hashing
	 verification = DEVICE_PARTIAL;
	 file->verification = DEVICE_PARTIAL;
      }
      if (verification == DEVICE_FULL) {
      // if (verification == DEVICE_PARTIAL || verification == DEVICE_FULL) { //cl3anup-partial should only be set by above if statement, no need for it here
	 //if (!file->probed) //cl3anup
            //probe_file_for_validation(file); //this would only be unprobed if you can't open it. all devices worth outputting to can be opened, sp just fail (make_file creates file->is_device=false) //cl3anup
         if (!file->is_device) //error out if user select full hash verification for a file
            report_error(DC3DD_EXIT_ABORTED, errno, 
               _("%s not recognized as a device, cannot specify fhod="), quote(file->name));
      }
      
      add_to_file_list(&settings->output_files, file);
   }
   else
      report_error(DC3DD_EXIT_ABORTED, 0, _("%s not valid BASE.FMT specifier for %s"),
        quote(file_name), verification != NONE ? "hofs=" : "ofs=");
}

static void
add_input_text_pattern(settings_t* settings, const char* pattern)
{
   // Note the early out for command line errors since evidence should not
   // be handled any more than necessary, and glossing over a malformed
   // command line is therefore undesirable - the user's choices need to be
   // exactly specified before a run is undertaken.

   if (settings->input_file || settings->input_pattern)
      report_error(DC3DD_EXIT_ABORTED, 0, _("use only one of pat=, tpat=, if=, ifs="));

   settings->input_pattern_string = strdup(pattern); 
   settings->input_pattern = strdup(pattern); 
   settings->input_pattern_length = strlen(pattern);     
}

static int 
hex_to_char(char *hstr)
{
   unsigned int retval;
   
   if (strlen(hstr) != 2)
   {
      return -1;
   }
   
   if (EOF == sscanf(hstr, "%x", &retval))
   {
      return -1;
   }

   return retval;
}

static void  
make_pattern(const char *pattern_template, char** pattern, size_t* pattern_length)
{
   *pattern = NULL;
   *pattern_length = 0;

   size_t pattern_template_length = strlen(pattern_template);
   if (pattern_template_length != 0 && pattern_template_length % 2 == 0)
   {
      *pattern_length = pattern_template_length / 2;
      *pattern = (char*)malloc(*pattern_length);

      for (size_t i = 0; i < *pattern_length; i++) 
      {
         char tmpstring[3];
         int byte_val;
         strncpy(tmpstring, &pattern_template[i*2], 2);
         tmpstring[2] = '\0';
         byte_val = hex_to_char(tmpstring);

         if (byte_val == -1) 
         {
            free(*pattern);
            *pattern = NULL;
            *pattern_length = 0;
         }
         
         (*pattern)[i] = (char)byte_val;
      }
   }
}

static void
add_input_pattern(settings_t* settings, const char* pattern)
{
   // Note the early outs for command line errors since evidence should not
   // be handled any more than necessary, and glossing over a malformed
   // command line is therefore undesirable - the user's choices need to be
   // exactly specified before a run is undertaken.

   if (settings->input_file || settings->input_pattern)
   {
      report_error(DC3DD_EXIT_ABORTED, 0, _("use only one of pat=, tpat=, if=, ifs="));
   }

   settings->input_pattern_string = strdup(pattern);
   make_pattern(pattern, &settings->input_pattern, &settings->input_pattern_length);
   if (!settings->input_pattern)
   {
      report_error(DC3DD_EXIT_ABORTED, 0, _("illegal pattern %s"), quote(pattern));
   }
}

static void
add_input_file(settings_t *settings, const char *file_name, bool part_of_set)
{
   
   if (settings->input_file || settings->input_pattern)
      report_error(DC3DD_EXIT_ABORTED, 0, _("use only one of pat=, tpat=, if=, ifs="));

   if (STREQ(file_name, "/dev/zero")) 
      add_input_pattern(settings, "00");
   else
   {
      settings->input_file = make_file(file_name, 0, O_RDONLY, part_of_set, NONE);
      if (!settings->input_file)
	 report_error(DC3DD_EXIT_ABORTED, 0 , _("%s not valid BASE.FMT form for ifs="), file_name);

      if (!STREQ(file_name, "stdin"))
	 probe_file_for_validation(settings->input_file);
   }
}

static bool
option_matches(const char* option, const char* option_name, char delim)
{
   while (*option_name)
   {
      if (*option++ != *option_name++)
      {
         return false;
      }
   }

   return !*option || *option == delim;
}

static bool
option_is(const char* option, const char* option_name)
{
   return option_matches(option, option_name, '=');
}

static uint64_t
parse_integer(const char* str, bool* invalid)
{
   uint64_t n;
   char *suffix;
   enum strtol_error e = xstrtoumax (str, &suffix, 10, &n, "bcEGkKMPTwYZ0");

   if (e == LONGINT_INVALID_SUFFIX_CHAR && *suffix == 'x')
   {
      uint64_t multiplier = parse_integer(suffix + 1, invalid);

      if (multiplier != 0 && n * multiplier / multiplier != n)
      {
         *invalid = true;
         return 0;
      }

      n *= multiplier;
   }
   else if (e != LONGINT_OK)
   {
      *invalid = true;
      return 0;
   }

   return n;
}

static void
parse_quantifier(settings_t* settings, const char* name, const char* val)
{
   // Note the early outs for command line errors since evidence should not
   // be handled any more than necessary, and glossing over a malformed
   // command line is therefore undesirable - the user's choices need to be
   // exactly specified before a run is undertaken.
   bool invalid = false;
   uint64_t n = 0;
   if (option_is (name, "ofsz"))
   {
      settings->max_output_file_size = n = parse_integer(val, &invalid);
   }
   else if (option_is(name, "bufsz"))
   {
      settings->buffer_size = n = parse_integer(val, &invalid);
   }
   else if (option_is(name, "iskip"))
   {
      settings->input_sectors_to_skip = n = parse_integer(val, &invalid);
   }
   else if (option_is(name, "oskip"))
   {
      settings->output_sectors_to_skip = n = parse_integer(val, &invalid);
   }
   else if (option_is(name, "cnt"))
   {	
      settings->max_sectors_to_input = n = parse_integer(val, &invalid);
   }
   else if (option_is(name, "ssz"))
   {
      settings->sector_size = n = parse_integer(val, &invalid);
   }
   else
   {
      report_error(DC3DD_EXIT_ABORTED, 0, _("unrecognized option %s"), name);
   }

   invalid |= !(n > 0);
   if (invalid)
   {
      report_error(DC3DD_EXIT_ABORTED, 0, _("invalid number %s for %s"), val, name);
   }
}

static void
validate_hashing_settings(settings_t* settings)
{
   // Note the early out for command line errors since evidence should not
   // be handled any more than necessary, and glossing over a malformed
   // command line is therefore undesirable - the user's choices need to be
   // exactly specified before a run is undertaken.

   // Determine whether there is an active hash algorithm.
   bool hash_specified = false;
   for (uint8_t i = 0; i < NUM_HASHES; ++i)
   {
      if (hash_algorithms[i].active)
      {
         hash_specified = true;
         break;
      }         
   }

   if (settings->verifying_output && !hash_specified)
   {
      report_error(DC3DD_EXIT_ABORTED, 0,
         _("hof=, hofs=, or hwipe= specified without hash algorithm(s) selection"));
   }
}   

static void
validate_size_settings(settings_t* settings)
{
   // Note the early outs for command line errors since evidence should not
   // be handled any more than necessary, and glossing over a malformed
   // command line is therefore undesirable - the user's choices need to be
   // exactly specified before a run is undertaken.
   
   // Determine the working sector size. 
   if (settings->wipe_target)
   {
      settings->sector_size = settings->wipe_target->probed_sector_size;
      settings->sector_size_source = _("probed");
   }
   else if (settings->sector_size > 0)
   {
      settings->sector_size_source = _("set");
   }
   else if (settings->input_file && 
            settings->input_file->is_device && 
            settings->input_file->probed_sector_size > 0)
   {
      settings->sector_size = settings->input_file->probed_sector_size;
      settings->sector_size_source = _("probed");
   }
   else
   {
      // This will be the case for regular files.
      settings->sector_size = DEFAULT_SECTOR_SIZE;
      settings->sector_size_source = _("assumed");
   }

   // Make sure the working sector size is consistent with the buffer size.
   if (settings->buffer_size < settings->sector_size || settings->buffer_size % settings->sector_size != 0)
   {
      // Do not reference bufsz=, since this may be an issue with the default buffer size. 
      report_error(DC3DD_EXIT_ABORTED, 0, _("buffer size (%d) must be a multiple of sector size (%d)"),
         settings->buffer_size, settings->sector_size);
   }

   // Make sure the skip sizes will work.
   if (settings->input_sectors_to_skip && 
       settings->input_file->probed_size_in_bytes < settings->input_sectors_to_skip)
   {
      report_error(DC3DD_EXIT_ABORTED, 0,
         _("if iskip= is specified, if= must specify an input file or device of at least that size"));
   }


   if (settings->output_sectors_to_skip)
   {
      file_t* file = settings->output_files;
      while (file)
      {
         // The output file must already exist if output sectors are to be skipped.
         probe_file_for_validation(file);
         if (file->probed_size_in_bytes < settings->output_sectors_to_skip * settings->sector_size)
         {
            report_error(DC3DD_EXIT_ABORTED, 0,
               _("if oskip= is specified, of= must specify output files of at least that size"));
         }
         file = file->next_file;
      }
   }
}

static void
validate_IO_options(settings_t* settings)
{
   // Make sure that the options specified are valid for the I\O combination. 
   // Note the early outs for command line errors since evidence should not
   // be handled any more than necessary, and glossing over a malformed
   // command line is therefore undesirable - the user's choices need to be
   // exactly specified before a run is undertaken.

   if (settings->input_pattern)
   {
      if (settings->input_sectors_to_skip)
      {
         report_error(DC3DD_EXIT_ABORTED, 0, _("cannot combine pat=, tpat= or if=/dev/zero and iskip="));
      }

      if (settings->max_sectors_to_input == INFINITE_SECTORS && !settings->wipe_target)
      {
         // Make sure a stopping condition exists, in the form of either a count of pattern sectors
         // to produce or the size of the device to be wiped.
	 report_error(DC3DD_EXIT_ABORTED, 0, _("if generating a pattern and not wiping, must specify cnt="));
      }
   }
 
   if (settings->input_file && settings->input_sectors_to_skip)
   {
      if (settings->input_file->part_of_set)
      {
	 // Not currently supporting the ability to skip input sectors if it requires opening
	 // multiple files. 
	 report_error(DC3DD_EXIT_ABORTED, 0, _("cannot combine cnt= and ifs="));                
      }

      if (STREQ(settings->input_file->name, "stdin"))
      {
	 report_error(DC3DD_EXIT_ABORTED, 0, _("cannot specify cnt= when input is stdin"));                

      }
   }

   if (settings->output_files && STREQ(settings->output_files->name, "stdout"))
   {
      if (settings->output_sectors_to_skip)
      {    
         report_error(DC3DD_EXIT_ABORTED, 0, _("cannot specify oskip= when output is stdout"));                
      }    

      if (settings->max_output_file_size != INFINITE_BYTES)
      {    
         report_error(DC3DD_EXIT_ABORTED, 0, _("cannot specify ofsz= when output is stdout"));                
      }    

      if (settings->append_output)
      {    
         report_error(DC3DD_EXIT_ABORTED, 0, _("cannot specify app=on when output is stdout"));                
      }    
   }

   if (settings->wipe_target)
   {
      if (settings->max_output_file_size != INFINITE_BYTES)
      {  
         report_error(DC3DD_EXIT_ABORTED, 0, _("cannot combine wipe= or hwipe= and ofsz="));                
      }    

      if (settings->max_sectors_to_input == INFINITE_SECTORS)
      {
         // Throttle the pattern input to the size of the device to be wiped, 
         // which is the sole output file.
         settings->max_sectors_to_input = settings->wipe_target->probed_size_in_sectors; 
      }
      else
      {    
         report_error(DC3DD_EXIT_ABORTED, 0, _("cannot combine wipe= or hwipe= and cnt="));                
      }    

      if (settings->input_sectors_to_skip)
      {    
         report_error(DC3DD_EXIT_ABORTED, 0, _("cannot combine wipe= or hwipe= and iskip="));                
      }    

      if (settings->output_sectors_to_skip)
      {    
         report_error(DC3DD_EXIT_ABORTED, 0, _("cannot combine wipe= or hwipe= and oskip="));                
      }    

      if (settings->append_output)
      {    
         report_error(DC3DD_EXIT_ABORTED, 0, _("cannot combine wipe= or hwipe= and app=on"));                
      }    
    
      if (settings->sector_size)
      {    
         report_error(DC3DD_EXIT_ABORTED, 0, _("cannot combine wipe= or hwipe= and ssz="));                
      }
   }

   if (settings->splitting_output)
   {
      if (settings->append_output)
      {
         report_error(DC3DD_EXIT_ABORTED, 0, _("cannot combine app=on and ofs= or hofs="));      
      }

      if (settings->output_sectors_to_skip)
      {    
	 // Not currently supporting the ability to skip output sectors if it requires opening
	 // multiple files. 
         report_error(DC3DD_EXIT_ABORTED, 0, _("cannot combine oskip= and ofs= of hofs="));                
      }    

      if (settings->max_output_file_size == INFINITE_BYTES)
      {
	 #ifdef DEFAULT_OUTPUT_FILE_SIZE
	 // This is necessary since the preprocessor symbol may have a size suffix.
	 parse_quantifier(settings, "ofsz", AS_STRING(DEFAULT_OUTPUT_FILE_SIZE));         
         #else
         report_error(DC3DD_EXIT_ABORTED, 0, _("ofs= or hofs= specified, must specify ofsz="));               
	 #endif
      }
   }
   else if (settings->max_output_file_size != INFINITE_BYTES)
   {
      report_error(DC3DD_EXIT_ABORTED, 0, _("ofsz= specified, must specify ofs= or hofs= at least once"));
   }   
} 

static void
validate_IO_combination(settings_t* settings)
{
   // Make sure that a valid combination of input and outputs is specified.
   // Note the early outs for command line errors since evidence should not
   // be handled any more than necessary, and glossing over a malformed
   // command line is therefore undesirable - the user's choices need to be
   // exactly specified before a run is undertaken.
   
   if (settings->wipe_target && settings->output_files)
   {
      report_error(DC3DD_EXIT_ABORTED, 0, _("cannot combine wipe= or hwipe= and of=, hof=, ofs= or hofs="));   
   }

   if (settings->wipe_target && settings->input_file)
   {
      report_error(DC3DD_EXIT_ABORTED, 0, _("cannot combine wipe= or hwipe= and if= or ifs="));      
   }

   if (settings->wipe_target && !settings->input_pattern)
   {
      // Wipe with zeros by default.
      add_input_pattern(settings, "00");
   }

   if (!settings->input_pattern && !settings->input_file)
   {
      // No inputs specified, default to reading from stdin.
      add_input_file(settings, "stdin", false);
   }
   
   if (!settings->wipe_target && !settings->output_files)
   {
      // No outputs specified, default to writing to stdout.
      add_output_file(settings, "stdout", false, NONE);
   }

   DC3DD_ASSERT((settings->wipe_target && settings->input_pattern) || 
                (!settings->wipe_target && settings->output_files &&
                (settings->input_file || settings->input_pattern)));
}

static void
validate_settings(settings_t* settings)
{
   // This function is decomposed into a series of shorter functions for
   // readability and maintainability. The order of calling of these functions
   // should be maintained.
   validate_IO_combination(settings);
   validate_IO_options(settings);
   validate_size_settings(settings);
   validate_hashing_settings(settings);
}

static settings_t*
make_settings()
{
   settings_t* settings = (settings_t*)malloc(sizeof(settings_t));
   settings->input_pattern_string = NULL;
   settings->input_pattern = NULL;
   settings->input_pattern_length = 0;
   settings->input_file = NULL;
   settings->output_files = NULL;
   settings->wipe_target = NULL;
   settings->sector_size = 0;
   settings->sector_size_source = NULL;
   settings->buffer_size = DEFAULT_BUFFER_SIZE;
   settings->input_sectors_to_skip = 0;
   settings->output_sectors_to_skip = 0;
   settings->max_sectors_to_input = INFINITE_SECTORS; 
   settings->max_output_file_size = INFINITE_BYTES;
   settings->recover_errors = true;
   settings->splitting_output = false;
   settings->verifying_output = false;
   settings->append_output = false;
   settings->corrupt_output = false;
   return settings;
} 

static settings_t*
parse_args(int argc, char *const *argv) {
   settings_t* settings = make_settings();

   // Note that parsing and validation of the command line is very strict
   // since evidence should not be handled any more than necessary. It is
   // therefore best if the user's choices are exactly specified before a
   // run is performed.
   for (int i = optind; i < argc; ++i) {
      // Split the argument into a name/value pair.
      char const *name = argv[i];
      char const *val = strchr(name, '=');
      if (!val) {
         report_error(DC3DD_EXIT_ABORTED, 0, _("unrecognized option %s"), quote(name));
      }
      ++val;

      if (option_is(name, "if")) {
         add_input_file(settings, val, false);
      }
      else if (option_is(name, "ifs")) {
         add_input_file(settings, val, true);         
      }
      else if (option_is(name,"pat")) {
         add_input_pattern(settings, val);
      }
      else if (option_is(name,"tpat")) {
         add_input_text_pattern(settings, val);
      }
      else if (option_is(name, "of")) {
         add_output_file(settings, val, false, NONE);
      }
      else if (option_is(name, "hof")) {
         add_output_file(settings, val, false, STANDARD);
      }
      //else if (option_is(name, "phod")) { //cl3anup
         //add_output_file(settings, val, false, DEVICE_PARTIAL); //cl3anup
      //} //cl3anup
      else if (option_is(name, "fhod")) {
         add_output_file(settings, val, false, DEVICE_FULL);
      }
      else if (option_is(name, "ofs")) {
         add_output_file(settings, val, true, NONE);
      }  
      else if (option_is(name, "hofs")) {
         add_output_file(settings, val, true, STANDARD);
      }  
      else if (option_is(name,"hash")) {
         activate_hash(val);      
      }
      else if (option_is(name,"log") || option_is(name, "hlog") || option_is(name,"mlog")) {
         if(option_is(name,"mlog"))
		{
			machine_report = true;
		}
      }
      else if (option_is(name,"rec")) {
         settings->recover_errors = false;
      }
      else if (option_is(name, "app")) {
         settings->append_output = true;
      }
      else if (option_is(name, "wipe")) {
         add_wipe_target(settings, val, false); 
      }
      else if (option_is(name, "hwipe")) {
         add_wipe_target(settings, val, true); 
      }
      else if (option_is(name, "verb")) {
         verbose_reporting = true;
      }
      else if (option_is(name, "nwspc")) {
         compact_reporting = true;
      }
      else if (option_is(name, "b10")) {
         progress_bytes_reporting_flag = 0;
      }
      else if (option_is(name, "corruptoutput")) {
         settings->corrupt_output = true;
      }
      else {
         parse_quantifier(settings, name, val);
      }
   }    
   
   return settings;
}

static settings_t*
parse_settings(int argc, char* const* argv)
{
   settings_t* settings = parse_args(argc, argv);
   validate_settings(settings);
   return settings;
}

static char* 
make_cmd_line_string(int argc, char* const* argv)
{
   size_t len = 1; // At least 1, for terminating NUL.

   for (int i = 0; i < argc; ++i)
   {
      len += strlen(argv[i]);
      if (i < (argc - 1))
      {
         len += 1;
      }
   }

   char* cmdline = NULL;
   cmdline = (char*)malloc(len);
   char* command_line = cmdline;
   for (int i = 0; i < argc; ++i)
   {
      for (size_t j = 0; j < strlen(argv[i]); ++j)
      {
         *cmdline = argv[i][j];
         ++cmdline;
      }

      if (i < (argc - 1))
      {
         *cmdline = ' ';
         ++cmdline;
      }
   }
   *cmdline = '\0';
   
   return command_line;
}

static void 
report_compile_flags(FILE* file, bool newlines)
{
   #ifdef DEFAULT_HASH_MD5
   fputs(" DEFAULT_HASH_MD5 (hash=md5)", file);
   if (newlines) fputs("\n", file);
   #endif

   #ifdef DEFAULT_HASH_SHA1
   fputs(" DEFAULT_HASH_SHA1 (hash=sha1)", file);
   if (newlines) fputs("\n", file);
   #endif

   #ifdef DEFAULT_HASH_SHA256
   fputs(" DEFAULT_HASH_SHA256 (hash=sha26)", file);
   if (newlines) fputs("\n", file);
   #endif

   #ifdef DEFAULT_HASH_SHA512
   fputs(" DEFAULT_HASH_SHA512 (hash=sha512)", file);
   if (newlines) fputs("\n", file);
   #endif

   #ifdef DEFAULT_OUTPUT_FILE_SIZE
   fprintf(file, " DEFAULT_OUTPUT_FILE_SIZE (ofsz=%s)", AS_STRING(DEFAULT_OUTPUT_FILE_SIZE));
   if (newlines) fputs("\n", file);
   #endif

   #ifdef DEFAULT_VERBOSE_REPORTING
   fputs(" DEFAULT_VERBOSE_REPORTING (verb=on)", file);
   if (newlines) fputs("\n", file);
   #endif

   #ifdef DEFAULT_COMPACT_REPORTING
   fputs(" DEFAULT_COMPACT_REPORTING (nwspc=on)", file);
   if (newlines) fputs("\n", file);
   #endif

   #ifdef DEFAULT_BASE_TEN_BYTES_REPORTING
   fputs(" DEFAULT_BASE_TEN_BYTES_REPORTING (dbr=on)", file);
   if (newlines) fputs("\n", file);
   #endif

   if (!newlines) fputs("\n", file);
}

static void
report_command_line(int argc, char* const* argv)
{
   // Report compiled-in options.
   fputs(_("compiled options:"), stderr);
   report_compile_flags(stderr, false);
   for (log_t* log = job_logs; log; log = log->next_log) {
      fputs(_("compiled options:"), log->file);
      report_compile_flags(log->file, false);
   }
   for (log_t* log = hash_logs; log; log = log->next_log) {
      fputs(_("compiled options:"), log->file);
      report_compile_flags(log->file, false);
   }

   // Report the command line.
   char* command_line = make_cmd_line_string(argc, argv);
   char message[DISPLAY_MESSAGE_LENGTH];
   sprintf(message, _("command line: %s\n"), command_line);
   report(message, ALL_LOGS);
   free(command_line);
   flush_logs();
}
 
static void
report_startup_message()
{
   // Save the program start time for later use in progress messages.
   start_time = gethrxtime();

   // Write the start message to all job_logs (i.e., console, log, hash log).
   // The message acts as a sort of header for the run. The leading newline
   // character acts to separate the output from multiple runs when
   // appending to an existing log.
   char* formatted_start_time = get_formatted_time_string();
   char message[DISPLAY_MESSAGE_LENGTH];
   sprintf(message, "\n%s %s started at %s\n", PROGRAM_NAME, VERSION, formatted_start_time);
   free(formatted_start_time);
   report(message, ALL_LOGS);
   flush_logs();
}

static void
open_log(const char *arg, const char *arg_name, log_t **logs)
{
   // Extract the log file name from the command line argument.
   const char *val = strchr(arg, '=');
   if (!val) {
      char message[DISPLAY_MESSAGE_LENGTH];
      sprintf(message, _("%s specified with no file name"), arg_name);
      report_error(DC3DD_EXIT_ABORTED, 0, message);
   }
   ++val;

   // Open the log file in append mode to support use cases where the
   // imaging is performed using multiple runs (e.g., using skips
   // etc., to work around errors) and a "cumulative" record of
   // the runs is desired.
   FILE *file = fopen(val, "a");
   if (!file)
      report_error(DC3DD_EXIT_ABORTED, errno, _("opening log %s"), quote(val));

   // Add the log to the logs list specified by the caller.
   log_t* log = (log_t*)malloc(sizeof(log_t));
   log->file = file;
   log->next_log = NULL;
   add_to_log_list(logs, log);

   // Add the log to the master logs list.
   log = (log_t*)malloc(sizeof(log_t));
   log->file = file;
   log->next_log = NULL;
   add_to_log_list(&all_logs, log);
}

static void 
initiate_logging(int argc, char* const* argv)
{
   // Initialize a mutex for synchronizing output to the log(s) and console.
   // Use PTHREAD_MUTEX_RECURSIVE so that nested calls to functions that lock
   // the mutex are safe.   
   pthread_mutexattr_t attr;
   pthread_mutexattr_init(&attr);
   pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
   pthread_mutex_init(&reporting_lock, &attr);
   pthread_mutexattr_destroy(&attr);

   // Look for command line options specifying job_logs.
   const char* arg = NULL;
   for (int i = optind; i < argc; ++i) {
      arg = argv[i];
      if (option_is(arg, "log")) {
         open_log(arg, "log=", &job_logs);
      }
      else if (option_is(arg, "hlog")) {
         open_log(arg, "hlog=", &hash_logs);
      }
	else if (option_is(arg,"mlog")){
		open_log(arg, "mlog=",&mach_logs);
	}
   }
}

void
usage(int status)
{
   if (status != EXIT_SUCCESS) {
      fprintf (stderr, _("Try `%s --help' for more information.\n"), program_name);
   }
   else {
      fputs(_("------\n"), stderr);
      fputs(_("usage:\n"), stderr);
      fputs(_("------\n\n"), stderr);
      fprintf(stderr, _("\t%s [OPTION 1] [OPTION 2] ... [OPTION N]\n"), program_name);    
      fputs("\n", stderr);
      fprintf(stderr, _("\t\t*or*\n"));    
      fputs("\n", stderr);
      fprintf(stderr, _("\t%s [HELP OPTION]\n"), program_name);    
      fputs("\n", stderr);
      fprintf(stderr, _("\twhere each OPTION is selected from the basic or advanced\n"));    
      fprintf(stderr, _("\toptions listed below, or HELP OPTION is selected from the\n"));    
      fprintf(stderr, _("\thelp options listed below.\n\n"));    

      fputs(_("--------------\n"), stderr);
      fputs(_("basic options:\n"), stderr);
      fputs(_("--------------\n\n"), stderr);
      fprintf(stderr, "\t%-21s%s\n", _("if=DEVICE or FILE"), _("Read input from a device or a file (see note #1"));
      fprintf(stderr, "\t%-21s%s\n", "", _("below for how to read from standard input). This"));
      fprintf(stderr, "\t%-21s%s\n", "", _("option can only be used once and cannot be"));
      fprintf(stderr, "\t%-21s%s\n", "", _("combined with ifs=, pat=, or tpat=."));
      if (!O_DIRECT) {
         fprintf(stderr, "\t%-21s%s\n", "", _("If FILE is a device, use rdisk for"));
         fprintf(stderr, "\t%-21s%s\n", "", _("direct (unbuffered) input to enable read error"));
         fprintf(stderr, "\t%-21s%s\n", "", _("recovery unless rec=off is specified."));
      }
      fprintf(stderr, "\t%-21s%s\n", _("ifs=BASE.FMT"), _("Read input from a set of files with base name"));
      fprintf(stderr, "\t%-21s%s\n", "", _("BASE and sequential file name extensions"));
      fprintf(stderr, "\t%-21s%s\n", "", _("conforming to the format specifier FMT (see note"));
      fprintf(stderr, "\t%-21s%s\n", "", _("#4 below for how to specify FMT). This option"));
      fprintf(stderr, "\t%-21s%s\n", "", _("can only be used once and cannot be combined with"));
      fprintf(stderr, "\t%-21s%s\n", "", _("if=, pat=, or tpat=."));
      fprintf(stderr, "\t%-21s%s\n", _("of=FILE or DEVICE"), _("Write output to a file or device (see note #2"));
      fprintf(stderr, "\t%-21s%s\n", "", _("below for how to write to standard output). This")); 
      fprintf(stderr, "\t%-21s%s\n", "", _("option can be used more than once (see note #3")); 
      fprintf(stderr, "\t%-21s%s\n", "", _("below for how to generate multiple outputs).")); 
      fprintf(stderr, "\t%-21s%s\n", _("hof=FILE or DEVICE"), _("Write output to a file or device, hash the"));
      fprintf(stderr, "\t%-21s%s\n", "", _("output bytes, and verify by comparing the output"));
      fprintf(stderr, "\t%-21s%s\n", "", _("hash(es) to the input hash(es). This option can"));
      fprintf(stderr, "\t%-21s%s\n", "", _("be used more than once (see note #3 below for"));
      fprintf(stderr, "\t%-21s%s\n", "", _("how to generate multiple outputs)."));
      fprintf(stderr, "\t%-21s%s\n", _("ofs=BASE.FMT"), _("Write output to a set of files with base name BASE"));
      fprintf(stderr, "\t%-21s%s\n", "", _("and sequential file name extensions generated from")); 
      fprintf(stderr, "\t%-21s%s\n", "", _("the format specifier FMT (see note #4 below for"));
      fprintf(stderr, "\t%-21s%s\n", "", _("how to specify FMT). This option can be used more"));
      fprintf(stderr, "\t%-21s%s\n", "", _("than once (see note #3 below for how to generate"));
      fprintf(stderr, "\t%-21s%s\n", "", _("multiple outputs). Specify the maximum size of"));
      fprintf(stderr, "\t%-21s%s\n", "", _("each file in the set using ofsz=."));
      fprintf(stderr, "\t%-21s%s\n", _("hofs=BASE.FMT"), _("Write output to a set of files with base name BASE"));
      fprintf(stderr, "\t%-21s%s\n", "", _("and sequential file name extensions generated from"));
      fprintf(stderr, "\t%-21s%s\n", "", _("the format specifier FMT (see note #4 below for"));
      fprintf(stderr, "\t%-21s%s\n", "", _("how to specify FMT). Hash the output files and"));
      fprintf(stderr, "\t%-21s%s\n", "", _("verify by comparing the output hash(es) to the"));
      fprintf(stderr, "\t%-21s%s\n", "", _("input hash(es). This option can be used more than"));
      fprintf(stderr, "\t%-21s%s\n", "", _("once (see note #3 below for how to generate"));
      fprintf(stderr, "\t%-21s%s\n", "", _("multiple outputs). Specify the maximum size of"));
      fprintf(stderr, "\t%-21s%s\n", "", _("each file in the set using ofsz=."));
      fprintf(stderr, "\t%-21s%s\n", _("ofsz=BYTES"), _("Set the maximum size of each file in the sets of"));
      fprintf(stderr, "\t%-21s%s\n", "", _("files specified using ofs= or hofs= to"));
      fprintf(stderr, "\t%-21s%s\n", "", _("BYTES (see note #5 below). A default value for"));
      fprintf(stderr, "\t%-21s%s\n", "", _("this option may be set at compile time using"));
      fprintf(stderr, "\t%-21s%s\n", "", _("-DDEFAULT_OUTPUT_FILE_SIZE followed by the desired"));
      fprintf(stderr, "\t%-21s%s\n", "", _("value in BYTES.")); 
      fprintf(stderr, "\t%-21s%s\n", _("hash=ALGORITHM"), _("Compute an ALGORITHM hash of the input and also"));
      fprintf(stderr, "\t%-21s%s\n", "", _("of any outputs specified using hof=, hofs=,"));
      fprintf(stderr, "\t%-21s%s\n", "", _("or fhod=, where ALGORITHM is one of md5, sha1,"));
      fprintf(stderr, "\t%-21s%s\n", "", _("sha256, or sha512. This option may be used once"));
      fprintf(stderr, "\t%-21s%s\n", "", _("for each supported ALGORITHM. Alternatively,"));
      fprintf(stderr, "\t%-21s%s\n", "", _("hashing can be activated at compile time using one"));
      fprintf(stderr, "\t%-21s%s\n", "", _("or more of -DDEFAULT_HASH_MD5,-DDEFAULT_HASH_SHA1,"));
      fprintf(stderr, "\t%-21s%s\n", "", _("-DDEFAULT_HASH_SHA256, and -DDEFAULT_HASH_SHA512.")); 
      fprintf(stderr, "\t%-21s%s\n", _("log=FILE"), _("Log I/O statistcs, diagnostics, and total hashes"));
      fprintf(stderr, "\t%-21s%s\n", "", _("of input and output to FILE. If hlog= is not"));
      fprintf(stderr, "\t%-21s%s\n", "", _("specified, piecewise hashes of multiple file"));
      fprintf(stderr, "\t%-21s%s\n", "", _("input and output are also logged to FILE. This"));
      fprintf(stderr, "\t%-21s%s\n", "", _("option can be used more than once to generate")); 
      fprintf(stderr, "\t%-21s%s\n", "", _("multiple logs.")); 
      fprintf(stderr, "\t%-21s%s\n", _("hlog=FILE"), _("Log total hashes and piecewise hashes to FILE."));
      fprintf(stderr, "\t%-21s%s\n", "", _("This option can be used more than once to generate")); 
      fprintf(stderr, "\t%-21s%s\n", "", _("multiple logs.")); 
      fprintf(stderr, "\t%-21s%s\n\n", _("mlog=FILE"),_("Create hash log that is easier for machine to read"));


      fputs(_("-----------------\n"), stderr);
      fputs(_("advanced options:\n"), stderr);
      fputs(_("-----------------\n\n"), stderr);
      //fprintf(stderr, "\t%-21s%s\n", _("phod=DEVICE"), _("Default behavior for hof=DEVICE, only the bytes")); //cl3anup
      //fprintf(stderr, "\t%-21s%s\n", "", _("written to DEVICE by dc3dd are verified. This")); //cl3anup
      //fprintf(stderr, "\t%-21s%s\n", "", _("option can be used more than once (see note #3")); //cl3anup
      //fprintf(stderr, "\t%-21s%s\n", "", _("below for how to generate multiple outputs).")); //cl3anup
      fprintf(stderr, "\t%-21s%s\n", _("fhod=DEVICE"), _("The same as hof=DEVICE, with additional"));
      fprintf(stderr, "\t%-21s%s\n", "", _("hashing of the entire output DEVICE. This option"));
      fprintf(stderr, "\t%-21s%s\n", "", _("can be used more than once (see note #3 below"));
      fprintf(stderr, "\t%-21s%s\n", "", _("for how to generate multiple outputs)."));
      fprintf(stderr, "\t%-21s%s\n", _("rec=off"), _("By default, zeros are written to the output(s) in"));
      fprintf(stderr, "\t%-21s%s\n", "", _("place of bad sectors when the input is a device."));
      fprintf(stderr, "\t%-21s%s\n", "", _("Use this option to cause the program to instead"));
      fprintf(stderr, "\t%-21s%s\n", "", _("exit when a bad sector is encountered.")); 
      fprintf(stderr, "\t%-21s%s\n", _("wipe=DEVICE"), _("Wipe DEVICE by writing zeros (default) or a"));
      fprintf(stderr, "\t%-21s%s\n", "", _("pattern specified by pat= or tpat=.")); 
      fprintf(stderr, "\t%-21s%s\n", _("hwipe=DEVICE"), _("Wipe DEVICE by writing zeros (default) or a"));
      fprintf(stderr, "\t%-21s%s\n", "", _("pattern specified by pat= or tpat=. Verify"));
      fprintf(stderr, "\t%-21s%s\n", "", _("DEVICE after writing it by hashing it and"));
      fprintf(stderr, "\t%-21s%s\n", "", _("comparing the hash(es) to the input hash(es)."));
      fprintf(stderr, "\t%-21s%s\n", _("pat=HEX"), _("Use pattern as input, writing HEX to every byte"));
      fprintf(stderr, "\t%-21s%s\n", "", _("of the output. This option can only be used once"));
      fprintf(stderr, "\t%-21s%s\n", "", _("and cannot be combined with if=, ifs=, or"));
      fprintf(stderr, "\t%-21s%s\n", "", _("tpat=."));
      fprintf(stderr, "\t%-21s%s\n", _("tpat=TEXT"), _("Use text pattern as input, writing the string TEXT"));
      fprintf(stderr, "\t%-21s%s\n", "", _("repeatedly to the output. This option can only be"));
      fprintf(stderr, "\t%-21s%s\n", "", _("used once and cannot be combined with if=, ifs=,"));
      fprintf(stderr, "\t%-21s%s\n", "", _("or pat=."));
      fprintf(stderr, "\t%-21s%s\n", _("cnt=SECTORS"), _("Read only SECTORS input sectors. Must be used"));
      fprintf(stderr, "\t%-21s%s\n", "", _("with pat= or tpat= if not using the pattern with"));
      fprintf(stderr, "\t%-21s%s\n", "", _("wipe= or hwipe= to wipe a device."));
      fprintf(stderr, "\t%-21s%s\n", _("iskip=SECTORS"), _("Skip SECTORS sectors at start of the input device"));
      fprintf(stderr, "\t%-21s%s\n", "", _("or file."));
      fprintf(stderr, "\t%-21s%s\n", _("oskip=SECTORS"), _("Skip SECTORS sectors at start of the output"));
      fprintf(stderr, "\t%-21s%s\n", "", _("file. Specifying oskip= automatically "));
      fprintf(stderr, "\t%-21s%s\n", "", _("sets app=on.")); 
      fprintf(stderr, "\t%-21s%s\n", _("app=on"), _("Do not overwrite an output file specified with"));
      fprintf(stderr, "\t%-21s%s\n", "", _("of= if it already exists, appending output instead.")); 
      fprintf(stderr, "\t%-21s%s\n", _("ssz=BYTES"), _("Unconditionally use BYTES (see note #5 below) bytes"));
      fprintf(stderr, "\t%-21s%s\n", "", _("for sector size. If ssz= is not specified,"));
      fprintf(stderr, "\t%-21s%s\n", "", _("sector size is determined by probing the device;"));
      fprintf(stderr, "\t%-21s%s\n", "", _("if the probe fails or the target is not a device,"));
      fprintf(stderr, "\t%-21s%s\n", "", _("a sector size of 512 bytes is assumed.")); 
      fprintf(stderr, "\t%-21s%s\n", _("bufsz=BYTES"), _("Set the size of the internal byte buffers to BYTES"));
      fprintf(stderr, "\t%-21s%s\n", "", _("(see note #5 below). This effectively sets the"));
      fprintf(stderr, "\t%-21s%s\n", "", _("maximum number of bytes that may be read at a time"));
      fprintf(stderr, "\t%-21s%s\n", "", _("from the input. BYTES must be a multiple of sector"));
      fprintf(stderr, "\t%-21s%s\n", "", _("size. Use this option to fine-tune performance."));
      fprintf(stderr, "\t%-21s%s\n", _("verb=on"), _("Activate verbose reporting, where sectors in/out"));
      fprintf(stderr, "\t%-21s%s\n", "", _("are reported for each file in sets of files"));
      fprintf(stderr, "\t%-21s%s\n", "", _("specified using ifs=, ofs=, or hofs=."));
      fprintf(stderr, "\t%-21s%s\n", "", _("Alternatively, verbose reporting may be activated"));
      fprintf(stderr, "\t%-21s%s\n", "", _("at compile time using -DDEFAULT_VERBOSE_REPORTING."));
      fprintf(stderr, "\t%-21s%s\n", _("nwspc=on"), _("Activate compact reporting, where the use"));
      fprintf(stderr, "\t%-21s%s\n", "", _("of white space to divide log output into"));
      fprintf(stderr, "\t%-21s%s\n", "", _("logical sections is suppressed. Alternatively,"));
      fprintf(stderr, "\t%-21s%s\n", "", _("compact reporting may be activated at compile"));
      fprintf(stderr, "\t%-21s%s\n", "", _("time using -DDEFAULT_COMPACT_REPORTING."));
      fprintf(stderr, "\t%-21s%s\n", _("b10=on"), _("Activate base 10 bytes reporting, where the"));
      fprintf(stderr, "\t%-21s%s\n", "", _("progress display reports 1000 bytes instead"));
      fprintf(stderr, "\t%-21s%s\n", "",  _("of 1024 bytes as 1 KB. Alternatively, base 10"));
      fprintf(stderr, "\t%-21s%s\n", "", _("bytes reporting may be activated at compile"));
      fprintf(stderr, "\t%-21s%s\n", "", _("time using -DDEFAULT_BASE_TEN_BYTES_REPORTING."));
      fprintf(stderr, "\t%-21s%s\n", _("corruptoutput=on"), _("For verification testing and demonstration"));
      fprintf(stderr, "\t%-21s%s\n", "", _("purposes, corrupt the output file(s) with extra"));       
      fprintf(stderr, "\t%-21s%s\n\n", "", _("bytes so a hash mismatch is guaranteed."));       

      fputs(_("-------------\n"), stderr);
      fputs(_("help options:\n"), stderr);
      fputs(_("-------------\n\n"), stderr);
      fputs (HELP_OPTION_DESCRIPTION, stderr);
      fputs (VERSION_OPTION_DESCRIPTION, stderr);
      fputs ("      --flags    display compile-time flags and exit\n\n", stderr);

      fputs(_("------\n"), stderr);
      fputs(_("notes:\n"), stderr);
      fputs(_("------\n\n"), stderr);
      fputs(_("1. To read from stdin, do not specify if=, ifs=, pat=, or tpat=.\n"), stderr);
      fputs(_("2. To write to stdout, do not specify of=, hof=, ofs=, hofs=, fhod=,\n"), stderr); 
      fputs(_("   wipe=, or hwipe=.\n"), stderr);
      fputs(_("3. To write to multiple outputs specify more than one of of=, hof=, ofs=,\n"), stderr);
      fputs(_("   hofs=, or fhod=, in any combination.\n"), stderr);
      fputs(_("4. FMT is a pattern for a sequence of file extensions that can be numerical\n"), stderr);
      fputs(_("   starting at zero, numerical starting at one, or alphabetical. Specify FMT\n"), stderr);
      fputs(_("   by using a series of zeros, ones, or a's, respectively. The number of\n"), stderr);
      fputs(_("   characters used indicates the desired length of the extensions.\n"), stderr);
      fputs(_("   For example, a FMT specifier of 0000 indicates four character\n"), stderr);
      fputs(_("   numerical extensions starting with 0000.\n"), stderr);  
      fputs(_("5. BYTES may be followed by the following multiplicative suffixes:\n"), stderr);
      fputs(_("   c (1), w (2), b (512), kB (1000), K (1024), MB (1000*1000),\n"), stderr);
      fputs(_("   M (1024*1024), GB (1000*1000*1000), G (1024*1024*1024), and\n"), stderr);
      fputs(_("   so on for T, P, E, Z, and Y.\n"), stderr);      
      fputs(_("6. Consider using cnt=, iskip= and oskip= to work around\n"), stderr);
      fputs(_("   unreadable sectors if error recovery fails.\n"), stderr);
      fputs(_("7. Sending an interrupt (e.g., CTRL+C) to dc3dd will cause\n"), stderr);
      fputs(_("   the program to report the work completed at the time\n"), stderr);
      fputs(_("   the interrupt is received and then exit.\n"), stderr);
      emit_bug_reporting_address();
   }
    
   report_exit_message(status);
   terminate_logging();
   exit(status);
}

int
main (int argc, char **argv)
{
   initialize_main(&argc, &argv);
   program_name = argv[0];

   // Set up localization support.
   setlocale(LC_ALL, "");
   bindtextdomain(PACKAGE, LOCALEDIR);
   textdomain(PACKAGE);

   // Handle the --flags command line option. 
   if (argc == 2 && STREQ(argv[1], "--flags")) {
      printf("%s compiled with:\n", PROGRAM_NAME);
      report_compile_flags(stdout, true);
      exit(DC3DD_EXIT_COMPLETED);
   }

   // Handle the --help and --version command line options. 
   parse_long_options(argc, argv, PROGRAM_NAME, PACKAGE, VERSION, usage, AUTHORS, (char const*)NULL);
   if (getopt_long(argc, argv, "", NULL, NULL) != -1) {
      usage(DC3DD_EXIT_FAILED);
   }
   
   initiate_logging(argc, argv);
   
   // Report startup info. 
   report_startup_message();
   report_command_line(argc, argv);

   // Do the requested jobs.
   settings_t* settings = parse_settings(argc, argv);
   report_input_size(settings);
   job_t* jobs = make_jobs(settings);
   int exit_code = execute_jobs(jobs);

   // Report results.
   report_results(jobs);
   report_exit_message(exit_code);

   terminate_logging();

   return exit_code;
}
