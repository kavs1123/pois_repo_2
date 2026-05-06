/**
 * Reduction Routing Table.
 *
 * Computes the shortest path between any two primitives in the Minicrypt clique
 * and chains the reductions.
 */

// ─── Primitives ─────────────────────────────────────────────────────────────
export const PRIMITIVES = ['OWF', 'OWP', 'PRG', 'PRF', 'PRP', 'MAC', 'CRHF', 'HMAC'];

// ─── Direct Reductions (forward A → B) ─────────────────────────────────────
const FORWARD_REDUCTIONS = {
  'OWF→PRG':  { chain: ['HILL hard-core-bit construction'], pa: [1], theorem: 'HILL Theorem' },
  'OWF→OWP':  { chain: ['DLP is already a OWP (identity)'], pa: [1], theorem: 'DLP as OWP' },
  'PRG→PRF':  { chain: ['GGM tree'], pa: [2], theorem: 'GGM Theorem' },
  'PRF→PRP':  { chain: ['Luby-Rackoff 3-round Feistel'], pa: [2], theorem: 'Luby-Rackoff Theorem' },
  'PRF→MAC':  { chain: ['Mac_k(m) = F_k(m)'], pa: [5], theorem: 'PRF-MAC Security' },
  'PRP→MAC':  { chain: ['PRP/PRF switching lemma', 'PRF→MAC'], pa: [2, 5], theorem: 'Switching Lemma + PRF-MAC' },
  'PRP→PRF':  { chain: ['PRP/PRF switching lemma'], pa: [2], theorem: 'Switching Lemma' },
  'CRHF→HMAC': { chain: ['HMAC construction'], pa: [10], theorem: 'HMAC Security (Bellare 2006)' },
  'HMAC→MAC':  { chain: ['HMAC is a MAC (direct)'], pa: [10], theorem: 'HMAC EUF-CMA Security' },
  'OWP→PRG':  { chain: ['Hard-core predicate extraction'], pa: [1], theorem: 'Goldreich-Levin + OWP→PRG' },
  'PRG→OWF':  { chain: ['f(s) = G(s) is a OWF'], pa: [1], theorem: 'PRG implies OWF' },
  'PRF→PRG':  { chain: ['G(s) = F_s(0) || F_s(1)'], pa: [2], theorem: 'PRF→PRG Construction' },
  'MAC→PRF':  { chain: ['MAC on random inputs is a PRF'], pa: [5], theorem: 'MAC→PRF (uniform inputs)' },
  'PRP→OWF':  { chain: ['f(k) = PRP_k(0^n) is a OWF'], pa: [2], theorem: 'PRP implies OWF' },
};

// ─── Graph for shortest path ────────────────────────────────────────────────

const EDGES = {};
for (const key of Object.keys(FORWARD_REDUCTIONS)) {
  const [from, to] = key.split('→');
  if (!EDGES[from]) EDGES[from] = [];
  EDGES[from].push(to);
}

/**
 * Find the shortest reduction chain from source to target using BFS.
 * @param {string} source - Source primitive
 * @param {string} target - Target primitive
 * @returns {{ path: string[], reductions: Array, supported: boolean, message: string }}
 */
export function getReductionChain(source, target) {
  if (source === target) {
    return { path: [source], reductions: [], supported: true, message: 'Identity (same primitive)' };
  }

  // BFS
  const visited = new Set();
  const queue = [[source]];
  visited.add(source);

  while (queue.length > 0) {
    const path = queue.shift();
    const current = path[path.length - 1];

    const neighbors = EDGES[current] || [];
    for (const next of neighbors) {
      if (next === target) {
        const fullPath = [...path, next];
        const reductions = [];
        for (let i = 0; i < fullPath.length - 1; i++) {
          const key = `${fullPath[i]}→${fullPath[i+1]}`;
          const red = FORWARD_REDUCTIONS[key];
          reductions.push({
            from: fullPath[i],
            to: fullPath[i+1],
            ...red,
          });
        }
        return { path: fullPath, reductions, supported: true, message: `${fullPath.join(' → ')}` };
      }
      if (!visited.has(next)) {
        visited.add(next);
        queue.push([...path, next]);
      }
    }
  }

  return {
    path: [],
    reductions: [],
    supported: false,
    message: `No direct reduction path from ${source} to ${target}. Try using the bidirectional toggle or a different source/target.`
  };
}

/**
 * Check if a primitive is implemented or just a stub.
 * @param {string} primitive - Primitive name
 * @returns {{ implemented: boolean, pa: number, label: string }}
 */
export function getPrimitiveStatus(primitive) {
  const IMPLEMENTED = {
    'OWF': { implemented: true, pa: 1, label: 'PA#1' },
    'OWP': { implemented: true, pa: 1, label: 'PA#1' },
    'PRG': { implemented: true, pa: 1, label: 'PA#1' },
    'PRF': { implemented: true, pa: 2, label: 'PA#2' },
    'PRP': { implemented: true, pa: 2, label: 'PA#2' },
    'CPA-ENC': { implemented: true, pa: 3, label: 'PA#3' },
    'MODES': { implemented: true, pa: 4, label: 'PA#4' },
    'MAC': { implemented: true, pa: 5, label: 'PA#5' },
    'CCA-ENC': { implemented: true, pa: 6, label: 'PA#6' },
    'CRHF': { implemented: true, pa: 8, label: 'PA#8' },
    'HMAC': { implemented: true, pa: 10, label: 'PA#10' },
  };

  return IMPLEMENTED[primitive] || { implemented: false, pa: '?', label: 'Unknown' };
}

/**
 * Get all reduction chain metadata for display.
 */
export function getAllReductions() {
  return FORWARD_REDUCTIONS;
}
