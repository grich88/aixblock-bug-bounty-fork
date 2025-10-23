import { CodeSandbox } from '../../core/code/code-sandbox-common'
import { v8IsolateCodeSandbox } from './v8-isolate-code-sandbox'

/**
 * SECURITY FIX: Replace unsafe no-op sandbox with secure V8 isolate sandbox
 * The original implementation used Function() constructor which allows arbitrary code execution
 */
export const secureCodeSandbox: CodeSandbox = {
    async runCodeModule({ codeModule, inputs }) {
        // Use secure V8 isolate sandbox instead of direct execution
        return v8IsolateCodeSandbox.runCodeModule({ codeModule, inputs })
    },

    async runScript({ script, scriptContext }) {
        // Use secure V8 isolate sandbox instead of Function() constructor
        return v8IsolateCodeSandbox.runScript({ script, scriptContext })
    },
}

// Keep the old name for backward compatibility but use secure implementation
export const noOpCodeSandbox = secureCodeSandbox
