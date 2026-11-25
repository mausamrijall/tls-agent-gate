/**
 * A tiny, dependency-free JSON Schema validator that covers the subset of
 * draft-07 used by the tls-agent-gate schemas:
 *
 *   - $ref (to #/definitions or #/$defs within the same document)
 *   - type (object / array / string / number / integer / boolean / null)
 *   - properties / required / additionalProperties
 *   - items (single schema form)
 *   - enum / const
 *   - minLength / maxLength / pattern
 *   - minimum / maximum
 *   - format: uri, date-time, hostname, ipv4
 *
 * This intentionally keeps `packages/core` zero-dependency (no ajv) while
 * still giving the CLI and runtime validators real schema checking.
 */

export interface SchemaObject {
  $schema?: string;
  $id?: string;
  $ref?: string;
  type?: string | string[];
  required?: string[];
  properties?: Record<string, SchemaObject>;
  additionalProperties?: boolean | SchemaObject;
  items?: SchemaObject;
  minItems?: number;
  maxItems?: number;
  enum?: unknown[];
  const?: unknown;
  minLength?: number;
  maxLength?: number;
  pattern?: string;
  minimum?: number;
  maximum?: number;
  format?: string;
  definitions?: Record<string, SchemaObject>;
  $defs?: Record<string, SchemaObject>;
  [key: string]: unknown;
}

export interface ValidationError {
  /** Dot-separated path to the offending value, e.g. `keys.primary.alg`. */
  path: string;
  message: string;
}

export interface ValidationResult {
  valid: boolean;
  errors: ValidationError[];
}

const DATE_TIME_RE =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;
const HOSTNAME_RE = /^(?=.{1,253}$)((?!-)[A-Za-z0-9-]{1,63}(?<!-))(\.((?!-)[A-Za-z0-9-]{1,63}(?<!-)))*$/;
const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

function resolveRef(ref: string, root: SchemaObject): SchemaObject | undefined {
  if (!ref.startsWith('#/')) return undefined;
  const parts = ref.slice(2).split('/').map((p) => p.replace(/~1/g, '/').replace(/~0/g, '~'));
  let node: unknown = root;
  for (const part of parts) {
    if (node && typeof node === 'object') {
      node = (node as Record<string, unknown>)[part];
    } else {
      return undefined;
    }
  }
  return node as SchemaObject | undefined;
}

function collect(
  value: unknown,
  schema: SchemaObject,
  root: SchemaObject,
  path: string,
  errors: ValidationError[],
): void {
  if (schema.$ref !== undefined) {
    const resolved = resolveRef(schema.$ref, root);
    if (!resolved) {
      errors.push({ path, message: `Unresolvable $ref: ${schema.$ref}` });
      return;
    }
    collect(value, resolved, root, path, errors);
    return;
  }

  // type
  if (schema.type !== undefined) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    const ok = types.some((t) => matchesType(value, t));
    if (!ok) {
      errors.push({ path, message: `Expected type ${types.join(' | ')}` });
      return;
    }
  }

  // enum / const
  if (schema.enum !== undefined) {
    if (!schema.enum.some((e) => deepEqual(e, value))) {
      errors.push({ path, message: 'Value is not one of the allowed enum values' });
      return;
    }
  }
  if (schema.const !== undefined && !deepEqual(schema.const, value)) {
    errors.push({ path, message: `Value must equal the const value` });
    return;
  }

  // object
  if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
    const obj = value as Record<string, unknown>;
    if (schema.required !== undefined) {
      for (const req of schema.required) {
        if (!(req in obj)) {
          errors.push({ path, message: `Missing required property "${req}"` });
        }
      }
    }
    if (schema.properties !== undefined) {
      for (const [key, sub] of Object.entries(schema.properties)) {
        if (key in obj) {
          collect(obj[key], sub, root, path ? `${path}.${key}` : key, errors);
        }
      }
    }
    if (schema.additionalProperties === false) {
      for (const key of Object.keys(obj)) {
        if (schema.properties && !(key in schema.properties)) {
          errors.push({ path, message: `Unexpected property "${key}"` });
        }
      }
    }
  }

  // array
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) {
      errors.push({ path, message: `Array has fewer than minItems ${schema.minItems} items` });
    }
    if (schema.maxItems !== undefined && value.length > schema.maxItems) {
      errors.push({ path, message: `Array has more than maxItems ${schema.maxItems} items` });
    }
    if (schema.items !== undefined) {
      for (let i = 0; i < value.length; i++) {
        collect(value[i], schema.items, root, `${path}[${i}]`, errors);
      }
    }
  }

  // string constraints
  if (typeof value === 'string') {
    if (schema.minLength !== undefined && value.length < schema.minLength) {
      errors.push({ path, message: `String is shorter than minLength ${schema.minLength}` });
    }
    if (schema.maxLength !== undefined && value.length > schema.maxLength) {
      errors.push({ path, message: `String is longer than maxLength ${schema.maxLength}` });
    }
    if (schema.pattern !== undefined && !new RegExp(schema.pattern).test(value)) {
      errors.push({ path, message: `String does not match pattern ${schema.pattern}` });
    }
    if (schema.format !== undefined) {
      if (!checkFormat(schema.format, value)) {
        errors.push({ path, message: `Invalid format ${schema.format}` });
      }
    }
  }

  // numeric constraints
  if (typeof value === 'number') {
    if (schema.minimum !== undefined && value < schema.minimum) {
      errors.push({ path, message: `Number is less than minimum ${schema.minimum}` });
    }
    if (schema.maximum !== undefined && value > schema.maximum) {
      errors.push({ path, message: `Number is greater than maximum ${schema.maximum}` });
    }
  }
}

function matchesType(value: unknown, type: string): boolean {
  switch (type) {
    case 'object':
      return typeof value === 'object' && value !== null && !Array.isArray(value);
    case 'array':
      return Array.isArray(value);
    case 'string':
      return typeof value === 'string';
    case 'number':
      return typeof value === 'number' && Number.isFinite(value);
    case 'integer':
      return typeof value === 'number' && Number.isInteger(value);
    case 'boolean':
      return typeof value === 'boolean';
    case 'null':
      return value === null;
    default:
      return true;
  }
}

function checkFormat(format: string, value: string): boolean {
  switch (format) {
    case 'uri': {
      try {
        // Only absolute URIs with a scheme qualify.
        const url = new URL(value);
        return url.protocol.length > 0;
      } catch {
        return false;
      }
    }
    case 'date-time':
      return DATE_TIME_RE.test(value);
    case 'hostname':
      return HOSTNAME_RE.test(value);
    case 'ipv4':
      return IPV4_RE.test(value);
    default:
      return true;
  }
}

function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (typeof a !== 'object' || a === null || b === null) return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  const aKeys = Object.keys(a as object);
  const bKeys = Object.keys(b as object);
  if (aKeys.length !== bKeys.length) return false;
  for (const key of aKeys) {
    if (!(key in (b as object))) return false;
    if (!deepEqual((a as Record<string, unknown>)[key], (b as Record<string, unknown>)[key])) return false;
  }
  return true;
}

/** Validate `value` against `schema` (draft-07 subset). */
export function validateSchema(value: unknown, schema: SchemaObject): ValidationResult {
  const errors: ValidationError[] = [];
  collect(value, schema, schema, '', errors);
  return { valid: errors.length === 0, errors };
}

export function isValid(value: unknown, schema: SchemaObject): boolean {
  return validateSchema(value, schema).valid;
}
