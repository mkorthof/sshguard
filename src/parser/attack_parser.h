/* A Bison parser, made by GNU Bison 2.3.  */

/* Skeleton interface for Bison's Yacc-like parsers in C

   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004, 2005, 2006
   Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301, USA.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     IPv4 = 258,
     IPv6 = 259,
     HOSTADDR = 260,
     WORD = 261,
     INTEGER = 262,
     SYSLOG_BANNER_PID = 263,
     LAST_LINE_REPEATED_N_TIMES = 264,
     SYSLOG_BANNER = 265,
     TIMESTAMP_SYSLOG = 266,
     TIMESTAMP_TAI64 = 267,
     METALOG_BANNER = 268,
     SSH_INVALUSERPREF = 269,
     SSH_NOTALLOWEDPREF = 270,
     SSH_NOTALLOWEDSUFF = 271,
     SSH_LOGINERR_PREF = 272,
     SSH_LOGINERR_SUFF = 273,
     SSH_LOGINERR_PAM = 274,
     SSH_REVERSEMAP_PREF = 275,
     SSH_REVERSEMAP_SUFF = 276,
     SSH_NOIDENTIFSTR = 277,
     SSH_BADPROTOCOLIDENTIF = 278,
     DOVECOT_IMAP_LOGINERR_PREF = 279,
     DOVECOT_IMAP_LOGINERR_SUFF = 280,
     UWIMAP_LOGINERR = 281,
     CYRUSIMAP_SASL_LOGINERR_PREF = 282,
     CYRUSIMAP_SASL_LOGINERR_SUFF = 283,
     CUCIPOP_AUTHFAIL = 284,
     EXIM_ESMTP_AUTHFAIL_PREF = 285,
     EXIM_ESMTP_AUTHFAIL_SUFF = 286,
     SENDMAIL_RELAYDENIED_PREF = 287,
     SENDMAIL_RELAYDENIED_SUFF = 288,
     FREEBSDFTPD_LOGINERR_PREF = 289,
     FREEBSDFTPD_LOGINERR_SUFF = 290,
     PROFTPD_LOGINERR_PREF = 291,
     PROFTPD_LOGINERR_SUFF = 292,
     PUREFTPD_LOGINERR_PREF = 293,
     PUREFTPD_LOGINERR_SUFF = 294,
     VSFTPD_LOGINERR_PREF = 295,
     VSFTPD_LOGINERR_SUFF = 296
   };
#endif
/* Tokens.  */
#define IPv4 258
#define IPv6 259
#define HOSTADDR 260
#define WORD 261
#define INTEGER 262
#define SYSLOG_BANNER_PID 263
#define LAST_LINE_REPEATED_N_TIMES 264
#define SYSLOG_BANNER 265
#define TIMESTAMP_SYSLOG 266
#define TIMESTAMP_TAI64 267
#define METALOG_BANNER 268
#define SSH_INVALUSERPREF 269
#define SSH_NOTALLOWEDPREF 270
#define SSH_NOTALLOWEDSUFF 271
#define SSH_LOGINERR_PREF 272
#define SSH_LOGINERR_SUFF 273
#define SSH_LOGINERR_PAM 274
#define SSH_REVERSEMAP_PREF 275
#define SSH_REVERSEMAP_SUFF 276
#define SSH_NOIDENTIFSTR 277
#define SSH_BADPROTOCOLIDENTIF 278
#define DOVECOT_IMAP_LOGINERR_PREF 279
#define DOVECOT_IMAP_LOGINERR_SUFF 280
#define UWIMAP_LOGINERR 281
#define CYRUSIMAP_SASL_LOGINERR_PREF 282
#define CYRUSIMAP_SASL_LOGINERR_SUFF 283
#define CUCIPOP_AUTHFAIL 284
#define EXIM_ESMTP_AUTHFAIL_PREF 285
#define EXIM_ESMTP_AUTHFAIL_SUFF 286
#define SENDMAIL_RELAYDENIED_PREF 287
#define SENDMAIL_RELAYDENIED_SUFF 288
#define FREEBSDFTPD_LOGINERR_PREF 289
#define FREEBSDFTPD_LOGINERR_SUFF 290
#define PROFTPD_LOGINERR_PREF 291
#define PROFTPD_LOGINERR_SUFF 292
#define PUREFTPD_LOGINERR_PREF 293
#define PUREFTPD_LOGINERR_SUFF 294
#define VSFTPD_LOGINERR_PREF 295
#define VSFTPD_LOGINERR_SUFF 296




#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
#line 78 "attack_parser.y"
{
    char *str;
    int num;
}
/* Line 1529 of yacc.c.  */
#line 136 "attack_parser.h"
	YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif

extern YYSTYPE yylval;

