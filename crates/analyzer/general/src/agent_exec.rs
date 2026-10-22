//! Autonomous-agent command execution: a language-model's output reaching a
//! shell, process spawn, or interpreter.
//!
//! This is the mechanism that turns an "AI agent" into one that runs commands
//! on its own — the model decides a string and the code executes it. An
//! attacker who can steer the model (a crafted web page, a poisoned tool
//! result, a prompt-injected document) then steers the host. It is the engine
//! of an autonomous offensive agent, and Truent reports it at critical
//! severity so a CI gate (`truent scan --fail-on high`) stops it from merging.
//!
//! The rule is deliberately narrow to stay high-signal: it fires only when a
//! value that originated from a model call reaches an execution sink
//! (`os.system`, `subprocess`, `child_process`, `exec.Command`, `eval`,
//! `exec`). A model result shown to a user, logged, or returned as data is not
//! reported.

use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashSet;
use truent_core::{Finding, Severity};

use crate::text::{code_lines_hash, code_lines_slash};
use crate::{finding, FileKind};

lazy_static! {
    static ref ASSIGN: Regex = Regex::new(
        r"^\s*(?:(?:export\s+)?(?:const|let|var)\s+)?([A-Za-z_$][A-Za-z0-9_$.,\s]*?)\s*(?::=|=)([^=].*)$"
    ).unwrap();
    static ref IDENT: Regex = Regex::new(r"[A-Za-z_$][A-Za-z0-9_$]*").unwrap();

    // A call to, or a response from, a language model / agent framework.
    static ref PY_LLM: Regex = Regex::new(
        r"\b(openai|anthropic|litellm|cohere|genai|google\.generativeai|ollama|replicate|together|groq|mistralai)\b|\.(chat\.completions|completions|messages|responses)\.(create|stream)\s*\(|\b(ChatOpenAI|ChatAnthropic|ChatOllama|ChatGoogleGenerativeAI|HuggingFaceHub|LLMChain|AgentExecutor)\b|\.(invoke|predict|run|generate|generate_content|complete)\s*\(|\.(choices|completion|output_text)\b|\bmessage\.content\b"
    ).unwrap();
    static ref PY_DECL: Regex = Regex::new(r"^\s*(async\s+)?def\s").unwrap();
    static ref PY_EXEC: Regex = Regex::new(
        r"\b(os\.system|os\.popen|subprocess\.(call|run|Popen|check_output|check_call)|eval|exec)\s*\("
    ).unwrap();

    static ref JS_LLM: Regex = Regex::new(
        r"\b(openai|anthropic|cohere|ollama|replicate|groq|mistral)\b|\.(chat\.completions|completions|messages|responses)\.(create|stream)\s*\(|\b(generateText|streamText|generateContent|createCompletion|ChatOpenAI|ChatAnthropic)\b|\.(invoke|generate|predict|run)\s*\(|\.(choices|completion|output_text)\b|\bmessage\.content\b"
    ).unwrap();
    static ref JS_DECL: Regex = Regex::new(
        r"^\s*(async\s+)?(function\b|(export\s+)?(async\s+)?(function|const|let|var)\s+\w+\s*=\s*(async\s*)?(function|\()|[A-Za-z_$][\w$]*\s*\([^)]*\)\s*(=>|\{)|[A-Za-z_$][\w$]*\s*:\s*(async\s*)?(function|\())"
    ).unwrap();
    static ref JS_EXEC: Regex = Regex::new(
        r"\b(exec|execSync|spawn|spawnSync|eval)\s*\(|new\s+Function\s*\("
    ).unwrap();

    static ref GO_LLM: Regex = Regex::new(
        r"\b(openai|anthropic|ollama|genai|cohere)\b|\.(CreateChatCompletion|CreateCompletion|Messages|Generate|Invoke)\s*\("
    ).unwrap();
    static ref GO_DECL: Regex = Regex::new(r"^\s*func\s").unwrap();
    static ref GO_EXEC: Regex = Regex::new(r"\bexec\.Command(Context)?\s*\(").unwrap();
}

/// Names assigned from a model call, propagated through later assignments.
fn detect_for(
    lines: &[String],
    file_path: &str,
    decl: &Regex,
    llm: &Regex,
    exec: &Regex,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut model_derived: HashSet<String> = HashSet::new();

    for (idx, line) in lines.iter().enumerate() {
        if decl.is_match(line) {
            model_derived.clear();
        }

        // A sink on this line reached by model output (inline or via a tracked
        // variable) is the finding.
        if let Some(m) = exec.find(line) {
            let args = &line[m.end()..];
            let inline = llm.is_match(args);
            let via_var = IDENT
                .find_iter(args)
                .any(|id| model_derived.contains(id.as_str()));
            if inline || via_var {
                out.push(finding(
                    "gen_agent_command_execution",
                    Severity::Critical,
                    file_path,
                    idx,
                    "A language model's output reaches command/code execution: whoever can steer \
                     the model (a prompt-injected page, tool result or document) runs commands on \
                     this host. Never execute model output; constrain the agent to a fixed, \
                     allow-listed set of tools with validated, structured arguments"
                        .to_string(),
                    line,
                ));
            }
        }

        // Track assignments: a value from a model call, or from an
        // already-tracked value, is model-derived. A clean reassignment clears.
        if let Some(c) = ASSIGN.captures(line) {
            let rhs = c.get(2).map(|m| m.as_str()).unwrap_or("");
            let becomes = llm.is_match(rhs)
                || IDENT
                    .find_iter(rhs)
                    .any(|id| model_derived.contains(id.as_str()));
            for name in c
                .get(1)
                .map(|m| m.as_str())
                .unwrap_or("")
                .split(',')
                .flat_map(|n| n.rsplit(['.', ' ']).next())
                .map(|n| n.trim().to_string())
                .filter(|n| !n.is_empty())
            {
                if becomes {
                    model_derived.insert(name);
                } else {
                    model_derived.remove(&name);
                }
            }
        }
    }
    out
}

/// Detect model output reaching execution, for one file.
pub fn detect(source: &str, file_path: &str, kind: FileKind) -> Vec<Finding> {
    match kind {
        FileKind::Python => detect_for(
            &code_lines_hash(source),
            file_path,
            &PY_DECL,
            &PY_LLM,
            &PY_EXEC,
        ),
        FileKind::JavaScript => detect_for(
            &code_lines_slash(source),
            file_path,
            &JS_DECL,
            &JS_LLM,
            &JS_EXEC,
        ),
        FileKind::Go => detect_for(
            &code_lines_slash(source),
            file_path,
            &GO_DECL,
            &GO_LLM,
            &GO_EXEC,
        ),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ids(src: &str, kind: FileKind) -> Vec<String> {
        detect(src, "f", kind)
            .into_iter()
            .map(|f| f.invariant_id)
            .collect()
    }

    #[test]
    fn python_model_output_to_os_system_is_flagged() {
        let src = "def act(goal):\n    resp = client.chat.completions.create(model='x', messages=m)\n    cmd = resp.choices[0].message.content\n    os.system(cmd)\n";
        assert!(ids(src, FileKind::Python).contains(&"gen_agent_command_execution".into()));
    }

    #[test]
    fn python_inline_model_call_to_exec_is_flagged() {
        let src = "def act():\n    exec(llm.invoke(prompt))\n";
        assert!(ids(src, FileKind::Python).contains(&"gen_agent_command_execution".into()));
    }

    #[test]
    fn js_model_output_to_child_process_is_flagged() {
        let src = "async function run(task) {\n  const r = await openai.chat.completions.create({ model: 'x', messages });\n  const cmd = r.choices[0].message.content;\n  execSync(cmd);\n}\n";
        assert!(ids(src, FileKind::JavaScript).contains(&"gen_agent_command_execution".into()));
    }

    #[test]
    fn model_output_shown_or_logged_is_not_flagged() {
        let py = "def chat(q):\n    resp = client.chat.completions.create(model='x', messages=m)\n    answer = resp.choices[0].message.content\n    print(answer)\n    return answer\n";
        assert!(ids(py, FileKind::Python).is_empty());
        let js = "async function ask(q) {\n  const r = await openai.chat.completions.create({ messages });\n  const a = r.choices[0].message.content;\n  res.json({ a });\n}\n";
        assert!(ids(js, FileKind::JavaScript).is_empty());
    }

    #[test]
    fn a_shell_command_from_a_constant_is_not_flagged() {
        let py = "def build():\n    cmd = 'ls -la'\n    os.system(cmd)\n";
        assert!(ids(py, FileKind::Python).is_empty());
    }

    #[test]
    fn taint_does_not_cross_function_boundaries() {
        let py = "def a():\n    cmd = llm.invoke(p)\n\ndef b(cmd):\n    os.system(cmd)\n";
        // `cmd` in b() is a fresh parameter, not the model-derived one from a().
        assert!(ids(py, FileKind::Python).is_empty());
    }
}
