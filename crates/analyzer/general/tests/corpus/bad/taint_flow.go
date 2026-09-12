// EXPECT: gen_command_injection
// Injection reached across several lines — no sink line contains a source.
package main

func ping(w http.ResponseWriter, r *http.Request) {
	host := r.FormValue("host")
	args := "ping -c 1 " + host
	exec.Command("sh", "-c", args).Run()
}
