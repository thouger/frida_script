import { Comparer, Comparison, EqualityComparer, MapLike, Queue, SortedArray, SortedReadonlyArray, TextSpan } from "./_namespaces/ts";
/** @internal */
export declare const emptyArray: never[];
/** @internal */
export declare const emptyMap: ReadonlyMap<never, never>;
/** @internal */
export declare const emptySet: ReadonlySet<never>;
/** @internal */
export declare function length(array: readonly any[] | undefined): number;
/**
 * Iterates through 'array' by index and performs the callback on each element of array until the callback
 * returns a truthy value, then returns that value.
 * If no such value is found, the callback is applied to each element of array and undefined is returned.
 *
 * @internal
 */
export declare function forEach<T, U>(array: readonly T[] | undefined, callback: (element: T, index: number) => U | undefined): U | undefined;
/**
 * Like `forEach`, but iterates in reverse order.
 *
 * @internal
 */
export declare function forEachRight<T, U>(array: readonly T[] | undefined, callback: (element: T, index: number) => U | undefined): U | undefined;
/**
 * Like `forEach`, but suitable for use with numbers and strings (which may be falsy).
 *
 * @internal
 */
export declare function firstDefined<T, U>(array: readonly T[] | undefined, callback: (element: T, index: number) => U | undefined): U | undefined;
/** @internal */
export declare function firstDefinedIterator<T, U>(iter: Iterable<T>, callback: (element: T) => U | undefined): U | undefined;
/** @internal */
export declare function reduceLeftIterator<T, U>(iterator: Iterable<T> | undefined, f: (memo: U, value: T, i: number) => U, initial: U): U;
/** @internal */
export declare function zipWith<T, U, V>(arrayA: readonly T[], arrayB: readonly U[], callback: (a: T, b: U, index: number) => V): V[];
/**
 * Creates a new array with `element` interspersed in between each element of `input`
 * if there is more than 1 value in `input`. Otherwise, returns the existing array.
 *
 * @internal
 */
export declare function intersperse<T>(input: T[], element: T): T[];
/**
 * Iterates through `array` by index and performs the callback on each element of array until the callback
 * returns a falsey value, then returns false.
 * If no such value is found, the callback is applied to each element of array and `true` is returned.
 *
 * @internal
 */
export declare function every<T, U extends T>(array: readonly T[], callback: (element: T, index: number) => element is U): array is readonly U[];
/** @internal */
export declare function every<T, U extends T>(array: readonly T[] | undefined, callback: (element: T, index: number) => element is U): array is readonly U[] | undefined;
/** @internal */
export declare function every<T>(array: readonly T[] | undefined, callback: (element: T, index: number) => boolean): boolean;
/**
 * Works like Array.prototype.find, returning `undefined` if no element satisfying the predicate is found.
 *
 * @internal
 */
export declare function find<T, U extends T>(array: readonly T[] | undefined, predicate: (element: T, index: number) => element is U, startIndex?: number): U | undefined;
/** @internal */
export declare function find<T>(array: readonly T[] | undefined, predicate: (element: T, index: number) => boolean, startIndex?: number): T | undefined;
/** @internal */
export declare function findLast<T, U extends T>(array: readonly T[] | undefined, predicate: (element: T, index: number) => element is U, startIndex?: number): U | undefined;
/** @internal */
export declare function findLast<T>(array: readonly T[] | undefined, predicate: (element: T, index: number) => boolean, startIndex?: number): T | undefined;
/**
 * Works like Array.prototype.findIndex, returning `-1` if no element satisfying the predicate is found.
 *
 * @internal
 */
export declare function findIndex<T>(array: readonly T[] | undefined, predicate: (element: T, index: number) => boolean, startIndex?: number): number;
/** @internal */
export declare function findLastIndex<T>(array: readonly T[] | undefined, predicate: (element: T, index: number) => boolean, startIndex?: number): number;
/**
 * Returns the first truthy result of `callback`, or else fails.
 * This is like `forEach`, but never returns undefined.
 *
 * @internal
 */
export declare function findMap<T, U>(array: readonly T[], callback: (element: T, index: number) => U | undefined): U;
/** @internal */
export declare function contains<T>(array: readonly T[] | undefined, value: T, equalityComparer?: EqualityComparer<T>): boolean;
/** @internal */
export declare function arraysEqual<T>(a: readonly T[], b: readonly T[], equalityComparer?: EqualityComparer<T>): boolean;
/** @internal */
export declare function indexOfAnyCharCode(text: string, charCodes: readonly number[], start?: number): number;
/** @internal */
export declare function countWhere<T>(array: readonly T[] | undefined, predicate: (x: T, i: number) => boolean): number;
/**
 * Filters an array by a predicate function. Returns the same array instance if the predicate is
 * true for all elements, otherwise returns a new array instance containing the filtered subset.
 *
 * @internal
 */
export declare function filter<T, U extends T>(array: T[], f: (x: T) => x is U): U[];
/** @internal */
export declare function filter<T>(array: T[], f: (x: T) => boolean): T[];
/** @internal */
export declare function filter<T, U extends T>(array: readonly T[], f: (x: T) => x is U): readonly U[];
/** @internal */
export declare function filter<T, U extends T>(array: readonly T[], f: (x: T) => boolean): readonly T[];
/** @internal */
export declare function filter<T, U extends T>(array: T[] | undefined, f: (x: T) => x is U): U[] | undefined;
/** @internal */
export declare function filter<T>(array: T[] | undefined, f: (x: T) => boolean): T[] | undefined;
/** @internal */
export declare function filter<T, U extends T>(array: readonly T[] | undefined, f: (x: T) => x is U): readonly U[] | undefined;
/** @internal */
export declare function filter<T, U extends T>(array: readonly T[] | undefined, f: (x: T) => boolean): readonly T[] | undefined;
/** @internal */
export declare function filterMutate<T>(array: T[], f: (x: T, i: number, array: T[]) => boolean): void;
/** @internal */
export declare function clear(array: unknown[]): void;
/** @internal */
export declare function map<T, U>(array: readonly T[], f: (x: T, i: number) => U): U[];
/** @internal */
export declare function map<T, U>(array: readonly T[] | undefined, f: (x: T, i: number) => U): U[] | undefined;
/** @internal */
export declare function mapIterator<T, U>(iter: Iterable<T>, mapFn: (x: T) => U): Generator<U, void, unknown>;
/**
 * Maps from T to T and avoids allocation if all elements map to themselves
 *
 * @internal */
export declare function sameMap<T, U = T>(array: T[], f: (x: T, i: number) => U): U[];
/** @internal */
export declare function sameMap<T, U = T>(array: readonly T[], f: (x: T, i: number) => U): readonly U[];
/** @internal */
export declare function sameMap<T, U = T>(array: T[] | undefined, f: (x: T, i: number) => U): U[] | undefined;
/** @internal */
export declare function sameMap<T, U = T>(array: readonly T[] | undefined, f: (x: T, i: number) => U): readonly U[] | undefined;
/**
 * Flattens an array containing a mix of array or non-array elements.
 *
 * @param array The array to flatten.
 *
 * @internal
 */
export declare function flatten<T>(array: T[][] | readonly (T | readonly T[] | undefined)[]): T[];
/**
 * Maps an array. If the mapped value is an array, it is spread into the result.
 *
 * @param array The array to map.
 * @param mapfn The callback used to map the result into one or more values.
 *
 * @internal
 */
export declare function flatMap<T, U>(array: readonly T[] | undefined, mapfn: (x: T, i: number) => U | readonly U[] | undefined): readonly U[];
/** @internal */
export declare function flatMapToMutable<T, U>(array: readonly T[] | undefined, mapfn: (x: T, i: number) => U | readonly U[] | undefined): U[];
/** @internal */
export declare function flatMapIterator<T, U>(iter: Iterable<T>, mapfn: (x: T) => readonly U[] | Iterable<U> | undefined): Generator<U, void, undefined>;
/**
 * Maps an array. If the mapped value is an array, it is spread into the result.
 * Avoids allocation if all elements map to themselves.
 *
 * @param array The array to map.
 * @param mapfn The callback used to map the result into one or more values.
 *
 * @internal
 */
export declare function sameFlatMap<T>(array: T[], mapfn: (x: T, i: number) => T | readonly T[]): T[];
/** @internal */
export declare function sameFlatMap<T>(array: readonly T[], mapfn: (x: T, i: number) => T | readonly T[]): readonly T[];
/** @internal */
export declare function mapAllOrFail<T, U>(array: readonly T[], mapFn: (x: T, i: number) => U | undefined): U[] | undefined;
/** @internal */
export declare function mapDefined<T, U>(array: readonly T[] | undefined, mapFn: (x: T, i: number) => U | undefined): U[];
/** @internal */
export declare function mapDefinedIterator<T, U>(iter: Iterable<T>, mapFn: (x: T) => U | undefined): Generator<U & ({} | null), void, unknown>;
/** @internal */
export declare function mapDefinedEntries<K1, V1, K2, V2>(map: ReadonlyMap<K1, V1>, f: (key: K1, value: V1) => readonly [K2, V2] | undefined): Map<K2, V2>;
/** @internal */
export declare function mapDefinedEntries<K1, V1, K2, V2>(map: ReadonlyMap<K1, V1> | undefined, f: (key: K1, value: V1) => readonly [K2 | undefined, V2 | undefined] | undefined): Map<K2, V2> | undefined;
/** @internal */
export declare function getOrUpdate<K, V>(map: Map<K, V>, key: K, callback: () => V): V;
/** @internal */
export declare function tryAddToSet<T>(set: Set<T>, value: T): boolean;
/** @internal */
export declare function singleIterator<T>(value: T): Generator<T, void, unknown>;
/**
 * Maps contiguous spans of values with the same key.
 *
 * @param array The array to map.
 * @param keyfn A callback used to select the key for an element.
 * @param mapfn A callback used to map a contiguous chunk of values to a single value.
 *
 * @internal
 */
export declare function spanMap<T, K, U>(array: readonly T[], keyfn: (x: T, i: number) => K, mapfn: (chunk: T[], key: K, start: number, end: number) => U): U[];
/** @internal */
export declare function spanMap<T, K, U>(array: readonly T[] | undefined, keyfn: (x: T, i: number) => K, mapfn: (chunk: T[], key: K, start: number, end: number) => U): U[] | undefined;
/** @internal */
export declare function mapEntries<K1, V1, K2, V2>(map: ReadonlyMap<K1, V1>, f: (key: K1, value: V1) => readonly [K2, V2]): Map<K2, V2>;
/** @internal */
export declare function mapEntries<K1, V1, K2, V2>(map: ReadonlyMap<K1, V1> | undefined, f: (key: K1, value: V1) => readonly [K2, V2]): Map<K2, V2> | undefined;
/** @internal */
export declare function some<T>(array: readonly T[] | undefined): array is readonly T[];
/** @internal */
export declare function some<T>(array: readonly T[] | undefined, predicate: (value: T) => boolean): boolean;
/**
 * Calls the callback with (start, afterEnd) index pairs for each range where 'pred' is true.
 *
 * @internal
 */
export declare function getRangesWhere<T>(arr: readonly T[], pred: (t: T) => boolean, cb: (start: number, afterEnd: number) => void): void;
/** @internal */
export declare function concatenate<T>(array1: T[], array2: T[]): T[];
/** @internal */
export declare function concatenate<T>(array1: readonly T[], array2: readonly T[]): readonly T[];
/** @internal */
export declare function concatenate<T>(array1: T[], array2: T[] | undefined): T[];
/** @internal */
export declare function concatenate<T>(array1: T[] | undefined, array2: T[]): T[];
/** @internal */
export declare function concatenate<T>(array1: readonly T[], array2: readonly T[] | undefined): readonly T[];
/** @internal */
export declare function concatenate<T>(array1: readonly T[] | undefined, array2: readonly T[]): readonly T[];
/** @internal */
export declare function concatenate<T>(array1: T[] | undefined, array2: T[] | undefined): T[] | undefined;
/** @internal */
export declare function concatenate<T>(array1: readonly T[] | undefined, array2: readonly T[] | undefined): readonly T[] | undefined;
/** @internal */
export declare function indicesOf(array: readonly unknown[]): number[];
/**
 * Deduplicates an unsorted array.
 * @param equalityComparer An `EqualityComparer` used to determine if two values are duplicates.
 * @param comparer An optional `Comparer` used to sort entries before comparison, though the
 * result will remain in the original order in `array`.
 *
 * @internal
 */
export declare function deduplicate<T>(array: readonly T[], equalityComparer: EqualityComparer<T>, comparer?: Comparer<T>): T[];
/** @internal */
export declare function createSortedArray<T>(): SortedArray<T>;
/** @internal */
export declare function insertSorted<T>(array: SortedArray<T>, insert: T, compare: Comparer<T>, allowDuplicates?: boolean): boolean;
/** @internal */
export declare function sortAndDeduplicate<T>(array: readonly string[]): SortedReadonlyArray<string>;
/** @internal */
export declare function sortAndDeduplicate<T>(array: readonly T[], comparer: Comparer<T>, equalityComparer?: EqualityComparer<T>): SortedReadonlyArray<T>;
/** @internal */
export declare function arrayIsSorted<T>(array: readonly T[], comparer: Comparer<T>): boolean;
/** @internal */
export declare const enum SortKind {
    None = 0,
    CaseSensitive = 1,
    CaseInsensitive = 2,
    Both = 3
}
/** @internal */
export declare function detectSortCaseSensitivity<T>(array: readonly T[], getString: (element: T) => string, compareStringsCaseSensitive: Comparer<string>, compareStringsCaseInsensitive: Comparer<string>): SortKind;
/** @internal */
export declare function arrayIsEqualTo<T>(array1: readonly T[] | undefined, array2: readonly T[] | undefined, equalityComparer?: (a: T, b: T, index: number) => boolean): boolean;
/**
 * Compacts an array, removing any falsey elements.
 *
 * @internal
 */
export declare function compact<T>(array: (T | undefined | null | false | 0 | "")[]): T[];
/** @internal */
export declare function compact<T>(array: readonly (T | undefined | null | false | 0 | "")[]): readonly T[];
/** @internal */
export declare function compact<T>(array: T[]): T[];
/** @internal */
export declare function compact<T>(array: readonly T[]): readonly T[];
/**
 * Gets the relative complement of `arrayA` with respect to `arrayB`, returning the elements that
 * are not present in `arrayA` but are present in `arrayB`. Assumes both arrays are sorted
 * based on the provided comparer.
 *
 * @internal
 */
export declare function relativeComplement<T>(arrayA: T[] | undefined, arrayB: T[] | undefined, comparer: Comparer<T>): T[] | undefined;
/**
 * Appends a value to an array, returning the array.
 *
 * @param to The array to which `value` is to be appended. If `to` is `undefined`, a new array
 * is created if `value` was appended.
 * @param value The value to append to the array. If `value` is `undefined`, nothing is
 * appended.
 *
 * @internal
 */
export declare function append<TArray extends any[] | undefined, TValue extends NonNullable<TArray>[number] | undefined>(to: TArray, value: TValue): [undefined, undefined] extends [TArray, TValue] ? TArray : NonNullable<TArray>[number][];
/** @internal */
export declare function append<T>(to: T[], value: T | undefined): T[];
/** @internal */
export declare function append<T>(to: T[] | undefined, value: T): T[];
/** @internal */
export declare function append<T>(to: T[] | undefined, value: T | undefined): T[] | undefined;
/** @internal */
export declare function append<T>(to: T[], value: T | undefined): void;
/**
 * Combines two arrays, values, or undefineds into the smallest container that can accommodate the resulting set:
 *
 * ```
 * undefined -> undefined -> undefined
 * T -> undefined -> T
 * T -> T -> T[]
 * T[] -> undefined -> T[] (no-op)
 * T[] -> T -> T[]         (append)
 * T[] -> T[] -> T[]       (concatenate)
 * ```
 *
 * @internal
 */
export declare function combine<T>(xs: T[] | undefined, ys: T[] | undefined): T[] | undefined;
/** @internal */
export declare function combine<T>(xs: T | readonly T[] | undefined, ys: T | readonly T[] | undefined): T | readonly T[] | undefined;
/** @internal */
export declare function combine<T>(xs: T | T[] | undefined, ys: T | T[] | undefined): T | T[] | undefined;
/**
 * Appends a range of value to an array, returning the array.
 *
 * @param to The array to which `value` is to be appended. If `to` is `undefined`, a new array
 * is created if `value` was appended.
 * @param from The values to append to the array. If `from` is `undefined`, nothing is
 * appended. If an element of `from` is `undefined`, that element is not appended.
 * @param start The offset in `from` at which to start copying values.
 * @param end The offset in `from` at which to stop copying values (non-inclusive).
 *
 * @internal
 */
export declare function addRange<T>(to: T[], from: readonly T[] | undefined, start?: number, end?: number): T[];
/** @internal */
export declare function addRange<T>(to: T[] | undefined, from: readonly T[] | undefined, start?: number, end?: number): T[] | undefined;
/**
 * @return Whether the value was added.
 *
 * @internal
 */
export declare function pushIfUnique<T>(array: T[], toAdd: T, equalityComparer?: EqualityComparer<T>): boolean;
/**
 * Unlike `pushIfUnique`, this can take `undefined` as an input, and returns a new array.
 *
 * @internal
 */
export declare function appendIfUnique<T>(array: T[] | undefined, toAdd: T, equalityComparer?: EqualityComparer<T>): T[];
/**
 * Returns a new sorted array.
 *
 * @internal
 */
export declare function sort<T>(array: readonly T[], comparer?: Comparer<T>): SortedReadonlyArray<T>;
/** @internal */
export declare function arrayReverseIterator<T>(array: readonly T[]): Generator<T, void, unknown>;
/**
 * Stable sort of an array. Elements equal to each other maintain their relative position in the array.
 *
 * @internal
 */
export declare function stableSort<T>(array: readonly T[], comparer: Comparer<T>): SortedReadonlyArray<T>;
/** @internal */
export declare function rangeEquals<T>(array1: readonly T[], array2: readonly T[], pos: number, end: number): boolean;
/**
 * Returns the element at a specific offset in an array if non-empty, `undefined` otherwise.
 * A negative offset indicates the element should be retrieved from the end of the array.
 *
 * @internal
 */
export declare const elementAt: <T>(array: readonly T[] | undefined, offset: number) => T | undefined;
/**
 * Returns the first element of an array if non-empty, `undefined` otherwise.
 *
 * @internal
 */
export declare function firstOrUndefined<T>(array: readonly T[] | undefined): T | undefined;
/** @internal */
export declare function firstOrUndefinedIterator<T>(iter: Iterable<T> | undefined): T | undefined;
/** @internal */
export declare function first<T>(array: readonly T[]): T;
/** @internal */
export declare function firstIterator<T>(iter: Iterable<T>): T;
/**
 * Returns the last element of an array if non-empty, `undefined` otherwise.
 *
 * @internal
 */
export declare function lastOrUndefined<T>(array: readonly T[] | undefined): T | undefined;
/** @internal */
export declare function last<T>(array: readonly T[]): T;
/**
 * Returns the only element of an array if it contains only one element, `undefined` otherwise.
 *
 * @internal
 */
export declare function singleOrUndefined<T>(array: readonly T[] | undefined): T | undefined;
/**
 * Returns the only element of an array if it contains only one element; throws otherwise.
 *
 * @internal
 */
export declare function single<T>(array: readonly T[]): T;
/**
 * Returns the only element of an array if it contains only one element; otherwise, returns the
 * array.
 *
 * @internal
 */
export declare function singleOrMany<T>(array: T[]): T | T[];
/** @internal */
export declare function singleOrMany<T>(array: readonly T[]): T | readonly T[];
/** @internal */
export declare function singleOrMany<T>(array: T[] | undefined): T | T[] | undefined;
/** @internal */
export declare function singleOrMany<T>(array: readonly T[] | undefined): T | readonly T[] | undefined;
/** @internal */
export declare function replaceElement<T>(array: readonly T[], index: number, value: T): T[];
/**
 * Performs a binary search, finding the index at which `value` occurs in `array`.
 * If no such index is found, returns the 2's-complement of first index at which
 * `array[index]` exceeds `value`.
 * @param array A sorted array whose first element must be no larger than number
 * @param value The value to be searched for in the array.
 * @param keySelector A callback used to select the search key from `value` and each element of
 * `array`.
 * @param keyComparer A callback used to compare two keys in a sorted array.
 * @param offset An offset into `array` at which to start the search.
 *
 * @internal
 */
export declare function binarySearch<T, U>(array: readonly T[], value: T, keySelector: (v: T) => U, keyComparer: Comparer<U>, offset?: number): number;
/**
 * Performs a binary search, finding the index at which an object with `key` occurs in `array`.
 * If no such index is found, returns the 2's-complement of first index at which
 * `array[index]` exceeds `key`.
 * @param array A sorted array whose first element must be no larger than number
 * @param key The key to be searched for in the array.
 * @param keySelector A callback used to select the search key from each element of `array`.
 * @param keyComparer A callback used to compare two keys in a sorted array.
 * @param offset An offset into `array` at which to start the search.
 *
 * @internal
 */
export declare function binarySearchKey<T, U>(array: readonly T[], key: U, keySelector: (v: T, i: number) => U, keyComparer: Comparer<U>, offset?: number): number;
/** @internal */
export declare function reduceLeft<T, U>(array: readonly T[] | undefined, f: (memo: U, value: T, i: number) => U, initial: U, start?: number, count?: number): U;
/** @internal */
export declare function reduceLeft<T>(array: readonly T[], f: (memo: T, value: T, i: number) => T): T | undefined;
/**
 * Indicates whether a map-like contains an own property with the specified key.
 *
 * @param map A map-like.
 * @param key A property key.
 *
 * @internal
 */
export declare function hasProperty(map: MapLike<any>, key: string): boolean;
/**
 * Gets the value of an owned property in a map-like.
 *
 * @param map A map-like.
 * @param key A property key.
 *
 * @internal
 */
export declare function getProperty<T>(map: MapLike<T>, key: string): T | undefined;
/**
 * Gets the owned, enumerable property keys of a map-like.
 *
 * @internal
 */
export declare function getOwnKeys<T>(map: MapLike<T>): string[];
/** @internal */
export declare function getAllKeys(obj: object): string[];
/** @internal */
export declare function getOwnValues<T>(collection: MapLike<T> | T[]): T[];
/** @internal */
export declare function arrayOf<T>(count: number, f: (index: number) => T): T[];
/**
 * Shims `Array.from`.
 *
 * @internal
 */
export declare function arrayFrom<T, U>(iterator: Iterable<T>, map: (t: T) => U): U[];
/** @internal */
export declare function arrayFrom<T>(iterator: Iterable<T>): T[];
/** @internal */
export declare function assign<T extends object>(t: T, ...args: (T | undefined)[]): T;
/**
 * Performs a shallow equality comparison of the contents of two map-likes.
 *
 * @param left A map-like whose properties should be compared.
 * @param right A map-like whose properties should be compared.
 *
 * @internal
 */
export declare function equalOwnProperties<T>(left: MapLike<T> | undefined, right: MapLike<T> | undefined, equalityComparer?: EqualityComparer<T>): boolean;
/**
 * Creates a map from the elements of an array.
 *
 * @param array the array of input elements.
 * @param makeKey a function that produces a key for a given element.
 *
 * This function makes no effort to avoid collisions; if any two elements produce
 * the same key with the given 'makeKey' function, then the element with the higher
 * index in the array will be the one associated with the produced key.
 *
 * @internal
 */
export declare function arrayToMap<K, V>(array: readonly V[], makeKey: (value: V) => K | undefined): Map<K, V>;
/** @internal */
export declare function arrayToMap<K, V1, V2>(array: readonly V1[], makeKey: (value: V1) => K | undefined, makeValue: (value: V1) => V2): Map<K, V2>;
/** @internal */
export declare function arrayToMap<T>(array: readonly T[], makeKey: (value: T) => string | undefined): Map<string, T>;
/** @internal */
export declare function arrayToMap<T, U>(array: readonly T[], makeKey: (value: T) => string | undefined, makeValue: (value: T) => U): Map<string, U>;
/** @internal */
export declare function arrayToNumericMap<T>(array: readonly T[], makeKey: (value: T) => number): T[];
/** @internal */
export declare function arrayToNumericMap<T, U>(array: readonly T[], makeKey: (value: T) => number, makeValue: (value: T) => U): U[];
/** @internal */
export declare function arrayToMultiMap<K, V>(values: readonly V[], makeKey: (value: V) => K): MultiMap<K, V>;
/** @internal */
export declare function arrayToMultiMap<K, V, U>(values: readonly V[], makeKey: (value: V) => K, makeValue: (value: V) => U): MultiMap<K, U>;
/** @internal */
export declare function group<T, K>(values: readonly T[], getGroupId: (value: T) => K): readonly (readonly T[])[];
/** @internal */
export declare function group<T, K, R>(values: readonly T[], getGroupId: (value: T) => K, resultSelector: (values: readonly T[]) => R): R[];
/** @internal */
export declare function group<T>(values: readonly T[], getGroupId: (value: T) => string): readonly (readonly T[])[];
/** @internal */
export declare function group<T, R>(values: readonly T[], getGroupId: (value: T) => string, resultSelector: (values: readonly T[]) => R): R[];
/** @internal */
export declare function groupBy<T, U extends T>(values: readonly T[] | undefined, keySelector: (value: T) => value is U): {
    true?: U[];
    false?: Exclude<T, U>[];
};
/** @internal */
export declare function groupBy<T, K extends string | number | boolean | null | undefined>(values: readonly T[] | undefined, keySelector: (value: T) => K): {
    [P in K as `${P}`]?: T[];
};
/** @internal */
export declare function clone<T>(object: T): T;
/**
 * Creates a new object by adding the own properties of `second`, then the own properties of `first`.
 *
 * NOTE: This means that if a property exists in both `first` and `second`, the property in `first` will be chosen.
 *
 * @internal
 */
export declare function extend<T1, T2>(first: T1, second: T2): T1 & T2;
/** @internal */
export declare function copyProperties<T1 extends T2, T2>(first: T1, second: T2): void;
/** @internal */
export declare function maybeBind<T, A extends any[], R>(obj: T, fn: ((this: T, ...args: A) => R) | undefined): ((...args: A) => R) | undefined;
/** @internal */
export interface MultiMap<K, V> extends Map<K, V[]> {
    /**
     * Adds the value to an array of values associated with the key, and returns the array.
     * Creates the array if it does not already exist.
     */
    add(key: K, value: V): V[];
    /**
     * Removes a value from an array of values associated with the key.
     * Does not preserve the order of those values.
     * Does nothing if `key` is not in `map`, or `value` is not in `map[key]`.
     */
    remove(key: K, value: V): void;
}
/** @internal */
export declare function createMultiMap<K, V>(): MultiMap<K, V>;
/** @internal */
export declare function createQueue<T>(items?: readonly T[]): Queue<T>;
/**
 * Creates a Set with custom equality and hash code functionality.  This is useful when you
 * want to use something looser than object identity - e.g. "has the same span".
 *
 * If `equals(a, b)`, it must be the case that `getHashCode(a) === getHashCode(b)`.
 * The converse is not required.
 *
 * To facilitate a perf optimization (lazy allocation of bucket arrays), `TElement` is
 * assumed not to be an array type.
 *
 * @internal
 */
export declare function createSet<TElement, THash = number>(getHashCode: (element: TElement) => THash, equals: EqualityComparer<TElement>): Set<TElement>;
/**
 * Tests whether a value is an array.
 *
 * @internal
 */
export declare function isArray(value: any): value is readonly unknown[];
/** @internal */
export declare function toArray<T>(value: T | T[]): T[];
/** @internal */
export declare function toArray<T>(value: T | readonly T[]): readonly T[];
/**
 * Tests whether a value is string
 *
 * @internal
 */
export declare function isString(text: unknown): text is string;
/** @internal */
export declare function isNumber(x: unknown): x is number;
/** @internal */
export declare function tryCast<TOut extends TIn, TIn = any>(value: TIn | undefined, test: (value: TIn) => value is TOut): TOut | undefined;
/** @internal */
export declare function cast<TOut extends TIn, TIn = any>(value: TIn | undefined, test: (value: TIn) => value is TOut): TOut;
/**
 * Does nothing.
 *
 * @internal
 */
export declare function noop(_?: unknown): void;
/**
 * Do nothing and return false
 *
 * @internal
 */
export declare function returnFalse(): false;
/**
 * Do nothing and return true
 *
 * @internal
 */
export declare function returnTrue(): true;
/**
 * Do nothing and return undefined
 *
 * @internal
 */
export declare function returnUndefined(): undefined;
/**
 * Returns its argument.
 *
 * @internal
 */
export declare function identity<T>(x: T): T;
/**
 * Returns lower case string
 *
 * @internal
 */
export declare function toLowerCase(x: string): string;
/**
 * Case insensitive file systems have descripencies in how they handle some characters (eg. turkish Upper case I with dot on top - \u0130)
 * This function is used in places where we want to make file name as a key on these systems
 * It is possible on mac to be able to refer to file name with I with dot on top as a fileName with its lower case form
 * But on windows we cannot. Windows can have fileName with I with dot on top next to its lower case and they can not each be referred with the lowercase forms
 * Technically we would want this function to be platform sepcific as well but
 * our api has till now only taken caseSensitive as the only input and just for some characters we dont want to update API and ensure all customers use those api
 * We could use upper case and we would still need to deal with the descripencies but
 * we want to continue using lower case since in most cases filenames are lowercasewe and wont need any case changes and avoid having to store another string for the key
 * So for this function purpose, we go ahead and assume character I with dot on top it as case sensitive since its very unlikely to use lower case form of that special character
 *
 * @internal
 */
export declare function toFileNameLowerCase(x: string): string;
/**
 * Throws an error because a function is not implemented.
 *
 * @internal
 */
export declare function notImplemented(): never;
/** @internal */
export declare function memoize<T>(callback: () => T): () => T;
/**
 * A version of `memoize` that supports a single primitive argument
 *
 * @internal
 */
export declare function memoizeOne<A extends string | number | boolean | undefined, T>(callback: (arg: A) => T): (arg: A) => T;
/**
 * A version of `memoize` that supports a single non-primitive argument, stored as keys of a WeakMap.
 *
 * @internal
 */
export declare function memoizeWeak<A extends object, T>(callback: (arg: A) => T): (arg: A) => T;
/** @internal */
export interface MemoizeCache<A extends any[], T> {
    has(args: A): boolean;
    get(args: A): T | undefined;
    set(args: A, value: T): void;
}
/**
 * A version of `memoize` that supports multiple arguments, backed by a provided cache.
 *
 * @internal
 */
export declare function memoizeCached<A extends any[], T>(callback: (...args: A) => T, cache: MemoizeCache<A, T>): (...args: A) => T;
/**
 * High-order function, composes functions. Note that functions are composed inside-out;
 * for example, `compose(a, b)` is the equivalent of `x => b(a(x))`.
 *
 * @param args The functions to compose.
 *
 * @internal
 */
export declare function compose<T>(...args: ((t: T) => T)[]): (t: T) => T;
/** @internal */
export declare const enum AssertionLevel {
    None = 0,
    Normal = 1,
    Aggressive = 2,
    VeryAggressive = 3
}
/**
 * Safer version of `Function` which should not be called.
 * Every function should be assignable to this, but this should not be assignable to every function.
 *
 * @internal
 */
export type AnyFunction = (...args: never[]) => void;
/** @internal */
export type AnyConstructor = new (...args: unknown[]) => unknown;
/** @internal */
export declare function equateValues<T>(a: T, b: T): boolean;
/**
 * Compare the equality of two strings using a case-sensitive ordinal comparison.
 *
 * Case-sensitive comparisons compare both strings one code-point at a time using the integer
 * value of each code-point after applying `toUpperCase` to each string. We always map both
 * strings to their upper-case form as some unicode characters do not properly round-trip to
 * lowercase (such as `ẞ` (German sharp capital s)).
 *
 * @internal
 */
export declare function equateStringsCaseInsensitive(a: string, b: string): boolean;
/**
 * Compare the equality of two strings using a case-sensitive ordinal comparison.
 *
 * Case-sensitive comparisons compare both strings one code-point at a time using the
 * integer value of each code-point.
 *
 * @internal
 */
export declare function equateStringsCaseSensitive(a: string, b: string): boolean;
/**
 * Compare two numeric values for their order relative to each other.
 * To compare strings, use any of the `compareStrings` functions.
 *
 * @internal
 */
export declare function compareValues(a: number | undefined, b: number | undefined): Comparison;
/**
 * Compare two TextSpans, first by `start`, then by `length`.
 *
 * @internal
 */
export declare function compareTextSpans(a: Partial<TextSpan> | undefined, b: Partial<TextSpan> | undefined): Comparison;
/** @internal */
export declare function min<T>(items: readonly [T, ...T[]], compare: Comparer<T>): T;
/** @internal */
export declare function min<T>(items: readonly T[], compare: Comparer<T>): T | undefined;
/**
 * Compare two strings using a case-insensitive ordinal comparison.
 *
 * Ordinal comparisons are based on the difference between the unicode code points of both
 * strings. Characters with multiple unicode representations are considered unequal. Ordinal
 * comparisons provide predictable ordering, but place "a" after "B".
 *
 * Case-insensitive comparisons compare both strings one code-point at a time using the integer
 * value of each code-point after applying `toUpperCase` to each string. We always map both
 * strings to their upper-case form as some unicode characters do not properly round-trip to
 * lowercase (such as `ẞ` (German sharp capital s)).
 *
 * @internal
 */
export declare function compareStringsCaseInsensitive(a: string, b: string): Comparison;
/**
 * `compareStringsCaseInsensitive` transforms letters to uppercase for unicode reasons,
 * while eslint's `sort-imports` rule transforms letters to lowercase. Which one you choose
 * affects the relative order of letters and ASCII characters 91-96, of which `_` is a
 * valid character in an identifier. So if we used `compareStringsCaseInsensitive` for
 * import sorting, TypeScript and eslint would disagree about the correct case-insensitive
 * sort order for `__String` and `Foo`. Since eslint's whole job is to create consistency
 * by enforcing nitpicky details like this, it makes way more sense for us to just adopt
 * their convention so users can have auto-imports without making eslint angry.
 *
 * @internal
 */
export declare function compareStringsCaseInsensitiveEslintCompatible(a: string, b: string): Comparison;
/**
 * Compare two strings using a case-sensitive ordinal comparison.
 *
 * Ordinal comparisons are based on the difference between the unicode code points of both
 * strings. Characters with multiple unicode representations are considered unequal. Ordinal
 * comparisons provide predictable ordering, but place "a" after "B".
 *
 * Case-sensitive comparisons compare both strings one code-point at a time using the integer
 * value of each code-point.
 *
 * @internal
 */
export declare function compareStringsCaseSensitive(a: string | undefined, b: string | undefined): Comparison;
/** @internal */
export declare function getStringComparer(ignoreCase?: boolean): typeof compareStringsCaseInsensitive;
/** @internal */
export declare function getUILocale(): string | undefined;
/** @internal */
export declare function setUILocale(value: string | undefined): void;
/**
 * Compare two strings in a using the case-sensitive sort behavior of the UI locale.
 *
 * Ordering is not predictable between different host locales, but is best for displaying
 * ordered data for UI presentation. Characters with multiple unicode representations may
 * be considered equal.
 *
 * Case-sensitive comparisons compare strings that differ in base characters, or
 * accents/diacritic marks, or case as unequal.
 *
 * @internal
 */
export declare function compareStringsCaseSensitiveUI(a: string, b: string): Comparison;
/** @internal */
export declare function compareProperties<T extends object, K extends keyof T>(a: T | undefined, b: T | undefined, key: K, comparer: Comparer<T[K]>): Comparison;
/**
 * True is greater than false.
 *
 * @internal
 */
export declare function compareBooleans(a: boolean, b: boolean): Comparison;
/**
 * Given a name and a list of names that are *not* equal to the name, return a spelling suggestion if there is one that is close enough.
 * Names less than length 3 only check for case-insensitive equality.
 *
 * find the candidate with the smallest Levenshtein distance,
 *    except for candidates:
 *      * With no name
 *      * Whose length differs from the target name by more than 0.34 of the length of the name.
 *      * Whose levenshtein distance is more than 0.4 of the length of the name
 *        (0.4 allows 1 substitution/transposition for every 5 characters,
 *         and 1 insertion/deletion at 3 characters)
 *
 * @internal
 */
export declare function getSpellingSuggestion<T>(name: string, candidates: T[], getName: (candidate: T) => string | undefined): T | undefined;
/** @internal */
export declare function endsWith(str: string, suffix: string): boolean;
/** @internal */
export declare function removeSuffix(str: string, suffix: string): string;
/** @internal */
export declare function tryRemoveSuffix(str: string, suffix: string): string | undefined;
/** @internal */
export declare function stringContains(str: string, substring: string): boolean;
/**
 * Takes a string like "jquery-min.4.2.3" and returns "jquery"
 *
 * @internal
 */
export declare function removeMinAndVersionNumbers(fileName: string): string;
/**
 * Remove an item from an array, moving everything to its right one space left.
 *
 * @internal
 */
export declare function orderedRemoveItem<T>(array: T[], item: T): boolean;
/**
 * Remove an item by index from an array, moving everything to its right one space left.
 *
 * @internal
 */
export declare function orderedRemoveItemAt<T>(array: T[], index: number): void;
/** @internal */
export declare function unorderedRemoveItemAt<T>(array: T[], index: number): void;
/**
 * Remove the *first* occurrence of `item` from the array.
 *
 * @internal
 */
export declare function unorderedRemoveItem<T>(array: T[], item: T): boolean;
/** @internal */
export type GetCanonicalFileName = (fileName: string) => string;
/** @internal */
export declare function createGetCanonicalFileName(useCaseSensitiveFileNames: boolean): GetCanonicalFileName;
/**
 * Represents a "prefix*suffix" pattern.
 *
 * @internal
 */
export interface Pattern {
    prefix: string;
    suffix: string;
}
/** @internal */
export declare function patternText({ prefix, suffix }: Pattern): string;
/**
 * Given that candidate matches pattern, returns the text matching the '*'.
 * E.g.: matchedText(tryParsePattern("foo*baz"), "foobarbaz") === "bar"
 *
 * @internal
 */
export declare function matchedText(pattern: Pattern, candidate: string): string;
/**
 * Return the object corresponding to the best pattern to match `candidate`.
 *
 * @internal
 */
export declare function findBestPatternMatch<T>(values: readonly T[], getPattern: (value: T) => Pattern, candidate: string): T | undefined;
/** @internal */
export declare function startsWith(str: string, prefix: string): boolean;
/** @internal */
export declare function removePrefix(str: string, prefix: string): string;
/** @internal */
export declare function tryRemovePrefix(str: string, prefix: string, getCanonicalFileName?: GetCanonicalFileName): string | undefined;
/** @internal */
export declare function isPatternMatch({ prefix, suffix }: Pattern, candidate: string): boolean;
/** @internal */
export declare function and<T>(f: (arg: T) => boolean, g: (arg: T) => boolean): (arg: T) => boolean;
/** @internal */
export declare function or<P, R1 extends P, R2 extends P>(f1: (p1: P) => p1 is R1, f2: (p2: P) => p2 is R2): (p: P) => p is R1 | R2;
/** @internal */
export declare function or<P, R1 extends P, R2 extends P, R3 extends P>(f1: (p1: P) => p1 is R1, f2: (p2: P) => p2 is R2, f3: (p3: P) => p3 is R3): (p: P) => p is R1 | R2 | R3;
/** @internal */
export declare function or<T extends unknown[], U>(...fs: ((...args: T) => U)[]): (...args: T) => U;
/** @internal */
export declare function not<T extends unknown[]>(fn: (...args: T) => boolean): (...args: T) => boolean;
/** @internal */
export declare function assertType<T>(_: T): void;
/** @internal */
export declare function singleElementArray<T>(t: T | undefined): T[] | undefined;
/** @internal */
export declare function enumerateInsertsAndDeletes<T, U>(newItems: readonly T[], oldItems: readonly U[], comparer: (a: T, b: U) => Comparison, inserted: (newItem: T) => void, deleted: (oldItem: U) => void, unchanged?: (oldItem: U, newItem: T) => void): boolean;
/** @internal */
export declare function cartesianProduct<T>(arrays: readonly T[][]): T[][];
/**
 * Returns string left-padded with spaces or zeros until it reaches the given length.
 *
 * @param s String to pad.
 * @param length Final padded length. If less than or equal to 's.length', returns 's' unchanged.
 * @param padString Character to use as padding (default " ").
 *
 * @internal
 */
export declare function padLeft(s: string, length: number, padString?: " " | "0"): string;
/**
 * Returns string right-padded with spaces until it reaches the given length.
 *
 * @param s String to pad.
 * @param length Final padded length. If less than or equal to 's.length', returns 's' unchanged.
 * @param padString Character to use as padding (default " ").
 *
 * @internal
 */
export declare function padRight(s: string, length: number, padString?: " "): string;
/** @internal */
export declare function takeWhile<T, U extends T>(array: readonly T[], predicate: (element: T) => element is U): U[];
/** @internal */
export declare function takeWhile<T, U extends T>(array: readonly T[] | undefined, predicate: (element: T) => element is U): U[] | undefined;
/** @internal */
export declare function skipWhile<T, U extends T>(array: readonly T[], predicate: (element: T) => element is U): Exclude<T, U>[];
/** @internal */
export declare function skipWhile<T, U extends T>(array: readonly T[] | undefined, predicate: (element: T) => element is U): Exclude<T, U>[] | undefined;
/**
 * Removes the leading and trailing white space and line terminator characters from a string.
 *
 * @internal
 */
export declare const trimString: (s: string) => string;
/**
 * Returns a copy with trailing whitespace removed.
 *
 * @internal
 */
export declare const trimStringEnd: (s: string) => string;
/**
 * Returns a copy with leading whitespace removed.
 *
 * @internal
 */
export declare const trimStringStart: (s: string) => string;
/** @internal */
export declare function isNodeLikeSystem(): boolean;
//# sourceMappingURL=core.d.ts.map