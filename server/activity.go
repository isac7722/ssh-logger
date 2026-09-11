package main

import "strings"

// A display-only classification. No records are discarded, and no attempt is
// made to infer who typed a command without process ancestry/shell input data.
// Evaluate at query time so existing records use the same rules as new records.
var routineReasonSQL = buildRoutineReasonSQL()

func sqlLiteral(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
func programSQL(names ...string) string {
	values := []string{}
	for _, name := range names {
		// Observed audit executable path on the monitored host.
		switch name {
		case "tr", "cut", "wc":
			values = append(values, sqlLiteral("/usr/lib/cargo/bin/coreutils/"+name))
		}
		for _, prefix := range []string{"", "/bin/", "/usr/bin/"} {
			values = append(values, sqlLiteral(prefix+name))
		}
	}
	return "e.program IN (" + strings.Join(values, ",") + ")"
}
func tailSQL(args ...string) string {
	values := []string{}
	for _, a := range args {
		values = append(values, sqlLiteral(a))
	}
	return "json_remove(e.args,'$[0]')=json_array(" + strings.Join(values, ",") + ")"
}
func buildRoutineReasonSQL() string {
	// Failed/unknown results and changed identities stay visible even when the
	// program looks like an environment probe. Unknown identity also stays visible.
	branches := []string{`CASE WHEN e.kind!='exec' OR e.outcome!='yes' OR e.user='' OR e.effective_user='' OR e.user!=e.effective_user THEN '' WHEN NOT json_valid(e.args) THEN '' WHEN json_type(e.args)!='array' THEN ''`}
	add := func(program, reason string, args ...string) {
		branches = append(branches, "WHEN ("+program+") AND ("+tailSQL(args...)+") THEN "+sqlLiteral(reason))
	}
	add(programSQL("getconf"), "환경 확인: 시스템 비트 수", "LONG_BIT")
	add(programSQL("lsb_release"), "환경 확인: 배포판 정보", "-a")
	for _, shell := range []string{"sh", "dash", "bash"} {
		add(programSQL(shell), "환경 확인: 배포판 정보", "/usr/bin/lsb_release", "-a")
	}
	add(programSQL("getopt"), "환경 확인: lsb_release 옵션 처리", "--name", "lsb_release", "-o", "hvidrcas", "-l", "help,version,id,description,release,codename,all,short", "--", "-a")
	for _, args := range [][]string{{"[:lower:]", "[:upper:]"}, {"[:upper:]", "[:lower:]"}} {
		add(programSQL("tr"), "보조 처리: 대소문자 변환", args...)
	}
	for _, arg := range []string{" ", "\n", " \n"} {
		add(programSQL("tr"), "보조 처리: 공백 정리", "-d", arg)
	}
	for _, arg := range []string{"\\n", "\n"} {
		add(programSQL("tr"), "보조 처리: 구분자 변환", arg, ":")
	}
	for _, arg := range []string{"-c1", "-c2-"} {
		add(programSQL("cut"), "보조 처리: 문자 추출", arg)
	}
	add(programSQL("wc"), "보조 처리: 표준 입력 행 수", "-l")
	add(programSQL("sed"), "보조 처리: 빈 줄 제거", "/^$/d")
	add(programSQL("awk"), "셸 초기화: 활성 옵션 확인", `$2=="on"{print $1}`)
	add(programSQL("locale"), "환경 확인: 로케일")
	add(programSQL("locale-check"), "환경 확인: 로케일 검사", "C.UTF-8")
	add(programSQL("run-parts"), "셸 초기화: 프로필 목록 확인", "--list", "--regex", "^[a-zA-Z0-9_][a-zA-Z0-9._-]*\\.sh$", "/etc/profile.d")
	add(programSQL("find"), "환경 확인: debuginfod 인증서 목록", "/etc/debuginfod", "-name", "*.certpath", "-print0")
	return strings.Join(append(branches, "ELSE '' END"), " ")
}
