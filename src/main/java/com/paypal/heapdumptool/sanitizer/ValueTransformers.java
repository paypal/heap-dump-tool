package com.paypal.heapdumptool.sanitizer;

import com.paypal.heapdumptool.utils.AbstractInvocationHandler;
import com.paypal.heapdumptool.utils.DataSize;
import com.paypal.heapdumptool.utils.DefaultMethodInvoker;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.function.DoubleUnaryOperator;
import java.util.function.IntUnaryOperator;
import java.util.function.LongUnaryOperator;

import static java.util.Objects.requireNonNull;

/**
 * Static factory methods for building a {@link ValueTransformer} from lambdas.
 *
 * <p>Each factory returns a {@link java.lang.reflect.Proxy} over {@link ValueTransformer}:
 *
 * <ul>
 *   <li>The targeted transform method delegates to the provided lambda; every other transform method
 *       keeps its default body (the identity transform).</li>
 *   <li>{@code describe()} returns the supplied description, or the factory method name when none is
 *       given.</li>
 *   <li>{@code maxMaterializedArraySize()} returns the declared limit, or the default (zero bytes)
 *       for the scalar factories.</li>
 *   <li>Every other method keeps its {@code default} interface body.</li>
 * </ul>
 *
 * <p>A factory-produced transformer behaves like any other {@link ValueTransformer} -- a lambda that
 * throws aborts the run, wrapped in {@link SanitizationRuleException} by the dispatch chain.
 *
 * <p>The functional interfaces the factories accept are nested here next to the factory that uses
 * them: BooleanFunction, ByteFunction, etc cover the primitive types. ArrayConsumer covers the
 * whole-array mode of the {@code *ArrayTransformer} factories.
 */
public final class ValueTransformers {

    private ValueTransformers() {
        throw new AssertionError();
    }

    /** A {@code boolean}-valued function. The JDK ships no {@code BooleanUnaryOperator}, so the factory uses this. */
    @FunctionalInterface
    public interface BooleanFunction {

        boolean apply(boolean value);
    }

    /** A transformer that only rewrites {@code boolean} values; every other type keeps its identity. */
    public static ValueTransformer booleanTransformer(final BooleanFunction transformer) {
        return booleanTransformer("booleanTransformer", transformer);
    }

    public static ValueTransformer booleanTransformer(final String desc, final BooleanFunction transformer) {
        return newProxy(new ScalarTransformerHandler(
                defaultDesc(desc, "booleanTransformer"),
                "transformBoolean",
                requireNonNull(transformer, "transformer")));
    }

    /** A {@code byte}-valued function. The JDK ships no {@code ByteUnaryOperator}, so the factory uses this. */
    @FunctionalInterface
    public interface ByteFunction {

        byte apply(byte value);
    }

    /** A transformer that only rewrites {@code byte} values; every other type keeps its identity. */
    public static ValueTransformer byteTransformer(final ByteFunction transformer) {
        return byteTransformer("byteTransformer", transformer);
    }

    public static ValueTransformer byteTransformer(final String desc, final ByteFunction transformer) {
        return newProxy(new ScalarTransformerHandler(
                defaultDesc(desc, "byteTransformer"), "transformByte", requireNonNull(transformer, "transformer")));
    }

    /** A {@code char}-valued function. The JDK ships no {@code CharUnaryOperator}, so the factory uses this. */
    @FunctionalInterface
    public interface CharFunction {

        char apply(char value);
    }

    /** A transformer that only rewrites {@code char} values; every other type keeps its identity. */
    public static ValueTransformer charTransformer(final CharFunction transformer) {
        return charTransformer("charTransformer", transformer);
    }

    public static ValueTransformer charTransformer(final String desc, final CharFunction transformer) {
        return newProxy(new ScalarTransformerHandler(
                defaultDesc(desc, "charTransformer"), "transformChar", requireNonNull(transformer, "transformer")));
    }

    /** A {@code short}-valued function. The JDK ships no {@code ShortUnaryOperator}, so the factory uses this. */
    @FunctionalInterface
    public interface ShortFunction {

        short apply(short value);
    }

    /** A transformer that only rewrites {@code short} values; every other type keeps its identity. */
    public static ValueTransformer shortTransformer(final ShortFunction transformer) {
        return shortTransformer("shortTransformer", transformer);
    }

    public static ValueTransformer shortTransformer(final String desc, final ShortFunction transformer) {
        return newProxy(new ScalarTransformerHandler(
                defaultDesc(desc, "shortTransformer"), "transformShort", requireNonNull(transformer, "transformer")));
    }

    /** A transformer that only rewrites {@code int} values; every other type keeps its identity. */
    public static ValueTransformer intTransformer(final IntUnaryOperator transformer) {
        return intTransformer("intTransformer", transformer);
    }

    public static ValueTransformer intTransformer(final String desc, final IntUnaryOperator transformer) {
        return newProxy(new ScalarTransformerHandler(
                defaultDesc(desc, "intTransformer"), "transformInt", requireNonNull(transformer, "transformer")));
    }

    /** A transformer that only rewrites {@code long} values; every other type keeps its identity. */
    public static ValueTransformer longTransformer(final LongUnaryOperator transformer) {
        return longTransformer("longTransformer", transformer);
    }

    public static ValueTransformer longTransformer(final String desc, final LongUnaryOperator transformer) {
        return newProxy(new ScalarTransformerHandler(
                defaultDesc(desc, "longTransformer"), "transformLong", requireNonNull(transformer, "transformer")));
    }

    /**
     * A {@code float}-valued unary operator. The JDK ships no {@code FloatUnaryOperator} -- only
     * {@code IntUnaryOperator}, {@code LongUnaryOperator} and {@code DoubleUnaryOperator} -- so the
     * float factory uses this one. Method name follows the JDK convention.
     */
    @FunctionalInterface
    public interface FloatUnaryOperator {

        float applyAsFloat(float value);
    }

    /** A transformer that only rewrites {@code float} values; every other type keeps its identity. */
    public static ValueTransformer floatTransformer(final FloatUnaryOperator transformer) {
        return floatTransformer("floatTransformer", transformer);
    }

    public static ValueTransformer floatTransformer(final String desc, final FloatUnaryOperator transformer) {
        return newProxy(new ScalarTransformerHandler(
                defaultDesc(desc, "floatTransformer"), "transformFloat", requireNonNull(transformer, "transformer")));
    }

    /** A transformer that only rewrites {@code double} values; every other type keeps its identity. */
    public static ValueTransformer doubleTransformer(final DoubleUnaryOperator transformer) {
        return doubleTransformer("doubleTransformer", transformer);
    }

    public static ValueTransformer doubleTransformer(final String desc, final DoubleUnaryOperator transformer) {
        return newProxy(new ScalarTransformerHandler(
                defaultDesc(desc, "doubleTransformer"), "transformDouble", requireNonNull(transformer, "transformer")));
    }

    /**
     * Consumes an array region as a whole, for the {@code *ArrayTransformer} factories.
     *
     * <p>Receives {@code (array, length, context)}: the region to process is {@code [0, length)}, the
     * argument array is engine scratch that may be longer, and the consumer must not retain it past the
     * call. The offset is always 0 in whole-array mode -- which is what {@code maxMaterializedArraySize}
     * opts into -- so it is omitted from this interface. Arrays larger than the declared limit fall back
     * to per-element transformation and never reach the consumer.
     */
    @FunctionalInterface
    public interface ArrayConsumer<T> {

        void consume(T array, int length, ArrayContext context);
    }

    /** A transformer that rewrites {@code boolean[]} contents as a whole. See {@link #byteArrayTransformer}. */
    public static ValueTransformer booleanArrayTransformer(
            final DataSize maxMaterializedArraySize, final ArrayConsumer<boolean[]> transformer) {
        return booleanArrayTransformer("booleanArrayTransformer", maxMaterializedArraySize, transformer);
    }

    public static ValueTransformer booleanArrayTransformer(
            final String desc, final DataSize maxMaterializedArraySize, final ArrayConsumer<boolean[]> transformer) {
        return arrayTransformer(
                desc, "booleanArrayTransformer", "transformBooleanArray", maxMaterializedArraySize, transformer);
    }

    /** A transformer that rewrites {@code char[]} contents as a whole. See {@link #byteArrayTransformer}. */
    public static ValueTransformer charArrayTransformer(
            final DataSize maxMaterializedArraySize, final ArrayConsumer<char[]> transformer) {
        return charArrayTransformer("charArrayTransformer", maxMaterializedArraySize, transformer);
    }

    public static ValueTransformer charArrayTransformer(
            final String desc, final DataSize maxMaterializedArraySize, final ArrayConsumer<char[]> transformer) {
        return arrayTransformer(
                desc, "charArrayTransformer", "transformCharArray", maxMaterializedArraySize, transformer);
    }

    /** A transformer that rewrites {@code short[]} contents as a whole. See {@link #byteArrayTransformer}. */
    public static ValueTransformer shortArrayTransformer(
            final DataSize maxMaterializedArraySize, final ArrayConsumer<short[]> transformer) {
        return shortArrayTransformer("shortArrayTransformer", maxMaterializedArraySize, transformer);
    }

    public static ValueTransformer shortArrayTransformer(
            final String desc, final DataSize maxMaterializedArraySize, final ArrayConsumer<short[]> transformer) {
        return arrayTransformer(
                desc, "shortArrayTransformer", "transformShortArray", maxMaterializedArraySize, transformer);
    }

    /** A transformer that rewrites {@code int[]} contents as a whole. See {@link #byteArrayTransformer}. */
    public static ValueTransformer intArrayTransformer(
            final DataSize maxMaterializedArraySize, final ArrayConsumer<int[]> transformer) {
        return intArrayTransformer("intArrayTransformer", maxMaterializedArraySize, transformer);
    }

    public static ValueTransformer intArrayTransformer(
            final String desc, final DataSize maxMaterializedArraySize, final ArrayConsumer<int[]> transformer) {
        return arrayTransformer(
                desc, "intArrayTransformer", "transformIntArray", maxMaterializedArraySize, transformer);
    }

    /** A transformer that rewrites {@code long[]} contents as a whole. See {@link #byteArrayTransformer}. */
    public static ValueTransformer longArrayTransformer(
            final DataSize maxMaterializedArraySize, final ArrayConsumer<long[]> transformer) {
        return longArrayTransformer("longArrayTransformer", maxMaterializedArraySize, transformer);
    }

    public static ValueTransformer longArrayTransformer(
            final String desc, final DataSize maxMaterializedArraySize, final ArrayConsumer<long[]> transformer) {
        return arrayTransformer(
                desc, "longArrayTransformer", "transformLongArray", maxMaterializedArraySize, transformer);
    }

    /** A transformer that rewrites {@code float[]} contents as a whole. See {@link #byteArrayTransformer}. */
    public static ValueTransformer floatArrayTransformer(
            final DataSize maxMaterializedArraySize, final ArrayConsumer<float[]> transformer) {
        return floatArrayTransformer("floatArrayTransformer", maxMaterializedArraySize, transformer);
    }

    public static ValueTransformer floatArrayTransformer(
            final String desc, final DataSize maxMaterializedArraySize, final ArrayConsumer<float[]> transformer) {
        return arrayTransformer(
                desc, "floatArrayTransformer", "transformFloatArray", maxMaterializedArraySize, transformer);
    }

    /** A transformer that rewrites {@code double[]} contents as a whole. See {@link #byteArrayTransformer}. */
    public static ValueTransformer doubleArrayTransformer(
            final DataSize maxMaterializedArraySize, final ArrayConsumer<double[]> transformer) {
        return doubleArrayTransformer("doubleArrayTransformer", maxMaterializedArraySize, transformer);
    }

    public static ValueTransformer doubleArrayTransformer(
            final String desc, final DataSize maxMaterializedArraySize, final ArrayConsumer<double[]> transformer) {
        return arrayTransformer(
                desc, "doubleArrayTransformer", "transformDoubleArray", maxMaterializedArraySize, transformer);
    }

    /**
     * Creates a transformer that receives the full array region as a contiguous slice.
     *
     * <p>{@link ArrayConsumer#consume(Object, int, ArrayContext)} receives {@code (array, length, context)}.
     * The offset is always 0 in whole-array mode, which {@code maxMaterializedArraySize} opts into, so it is
     * omitted from the functional interface. The consumer must not retain the array past the call.</p>
     *
     * <p>Arrays larger than {@code maxMaterializedArraySize} fall back to per-element transformation
     * (the default {@code transformByteArray} behaviour) and the fallback is logged.</p>
     */
    public static ValueTransformer byteArrayTransformer(
            final DataSize maxMaterializedArraySize, final ArrayConsumer<byte[]> transformer) {
        return byteArrayTransformer("byteArrayTransformer", maxMaterializedArraySize, transformer);
    }

    public static ValueTransformer byteArrayTransformer(
            final String desc, final DataSize maxMaterializedArraySize, final ArrayConsumer<byte[]> transformer) {
        return arrayTransformer(
                desc, "byteArrayTransformer", "transformByteArray", maxMaterializedArraySize, transformer);
    }

    private static ValueTransformer arrayTransformer(
            final String desc,
            final String defaultDesc,
            final String methodName,
            final DataSize maxMaterializedArraySize,
            final ArrayConsumer<?> transformer) {
        return newProxy(new ArrayTransformerHandler(
                defaultDesc(desc, defaultDesc),
                methodName,
                requireNonNull(maxMaterializedArraySize, "maxMaterializedArraySize"),
                requireNonNull(transformer, "transformer")));
    }

    /**
     * Combines transformers as a sequential pipeline: for each primitive type, each transformer's output is
     * the next transformer's input. In-place array methods are applied in order over the same slice.
     *
     * <p>All transformers must agree on {@code maxMaterializedArraySize()}. Throws
     * {@link IllegalArgumentException} at construction time if they differ.</p>
     */
    public static ValueTransformer combine(final List<ValueTransformer> transformers) {
        return combine(null, transformers);
    }

    public static ValueTransformer combine(final String desc, final List<ValueTransformer> transformers) {
        if (transformers == null || transformers.isEmpty()) {
            throw new IllegalArgumentException("At least one transformer is required");
        }
        final DataSize limit = transformers.get(0).maxMaterializedArraySize();
        for (int i = 1; i < transformers.size(); i++) {
            final DataSize other = transformers.get(i).maxMaterializedArraySize();
            if (!limit.equals(other)) {
                throw new IllegalArgumentException(
                        "Cannot combine transformers with different maxMaterializedArraySize: " + limit + " vs " + other
                                + " (transformer " + i + " differs)");
            }
        }
        return newProxy(new CombinedTransformerHandler(desc, transformers, limit));
    }

    private static ValueTransformer newProxy(final AbstractInvocationHandler handler) {
        return (ValueTransformer) Proxy.newProxyInstance(
                ValueTransformer.class.getClassLoader(), new Class<?>[] {ValueTransformer.class}, handler);
    }

    private static String defaultDesc(final String desc, final String defaultDesc) {
        return desc == null ? defaultDesc : desc;
    }

    private static boolean is(final Method method, final String name, final int paramCount) {
        return method.getName().equals(name) && method.getParameterCount() == paramCount;
    }

    /** A proxy that routes one scalar transform method to a lambda; every other method keeps its default body. */
    private static final class ScalarTransformerHandler extends AbstractInvocationHandler {

        private final String desc;
        private final String methodName;
        private final Object function;

        ScalarTransformerHandler(final String desc, final String methodName, final Object function) {
            this.desc = desc;
            this.methodName = methodName;
            this.function = function;
        }

        @Override
        protected Object handleInvocation(final Object proxy, final Method method, final Object[] args)
                throws Throwable {
            if (is(method, methodName, 1)) {
                return transform(args[0]);
            }
            if (is(method, "describe", 0)) {
                return desc;
            }
            if (method.getDeclaringClass().isInterface() && method.isDefault()) {
                return DefaultMethodInvoker.invoke(proxy, method, args);
            }
            throw new UnsupportedOperationException(methodName + " transformer proxy: unexpected method " + method);
        }

        private Object transform(final Object value) {
            if (methodName.equals("transformBoolean")) {
                return ((BooleanFunction) function).apply((Boolean) value);
            }
            if (methodName.equals("transformByte")) {
                return ((ByteFunction) function).apply((Byte) value);
            }
            if (methodName.equals("transformChar")) {
                return ((CharFunction) function).apply((Character) value);
            }
            if (methodName.equals("transformShort")) {
                return ((ShortFunction) function).apply((Short) value);
            }
            if (methodName.equals("transformInt")) {
                return ((IntUnaryOperator) function).applyAsInt((Integer) value);
            }
            if (methodName.equals("transformLong")) {
                return ((LongUnaryOperator) function).applyAsLong((Long) value);
            }
            if (methodName.equals("transformFloat")) {
                return ((FloatUnaryOperator) function).applyAsFloat((Float) value);
            }
            if (methodName.equals("transformDouble")) {
                return ((DoubleUnaryOperator) function).applyAsDouble((Double) value);
            }
            throw new IllegalStateException("Unknown transform method: " + methodName);
        }
    }

    /** A proxy that routes one {@code transformXxxArray} method to a whole-array consumer; every other method keeps its default body. */
    private static final class ArrayTransformerHandler extends AbstractInvocationHandler {

        private final String desc;
        private final String arrayMethodName;
        private final ArrayConsumer<?> transformer;
        private final DataSize maxMaterializedArraySize;

        ArrayTransformerHandler(
                final String desc,
                final String arrayMethodName,
                final DataSize maxMaterializedArraySize,
                final ArrayConsumer<?> transformer) {
            this.desc = desc;
            this.arrayMethodName = arrayMethodName;
            this.transformer = transformer;
            this.maxMaterializedArraySize = maxMaterializedArraySize;
        }

        @Override
        protected Object handleInvocation(final Object proxy, final Method method, final Object[] args)
                throws Throwable {
            if (is(method, arrayMethodName, 3)) {
                consume(args[0], (Integer) args[1], (ArrayContext) args[2]);
                return null;
            }
            if (is(method, "maxMaterializedArraySize", 0)) {
                return maxMaterializedArraySize;
            }
            if (is(method, "describe", 0)) {
                return desc;
            }
            if (method.getDeclaringClass().isInterface() && method.isDefault()) {
                return DefaultMethodInvoker.invoke(proxy, method, args);
            }
            throw new UnsupportedOperationException(
                    arrayMethodName + " transformer proxy: unexpected method " + method);
        }

        @SuppressWarnings("unchecked")
        private void consume(final Object array, final int length, final ArrayContext context) {
            ((ArrayConsumer<Object>) transformer).consume(array, length, context);
        }
    }

    /** A proxy that fans every transform method out to the component transformers in order. */
    private static final class CombinedTransformerHandler extends AbstractInvocationHandler {

        private final String desc;
        private final List<ValueTransformer> transformers;
        private final DataSize maxMaterializedArraySize;

        CombinedTransformerHandler(
                final String desc, final List<ValueTransformer> transformers, final DataSize maxMaterializedArraySize) {
            this.desc = desc;
            this.transformers = transformers;
            this.maxMaterializedArraySize = maxMaterializedArraySize;
        }

        @Override
        protected Object handleInvocation(final Object proxy, final Method method, final Object[] args)
                throws Throwable {
            if (isTransformMethod(method)) {
                return chain(method, args);
            }
            if (is(method, "maxMaterializedArraySize", 0)) {
                return maxMaterializedArraySize;
            }
            if (is(method, "describe", 0)) {
                return combinedDescription();
            }
            if (method.getDeclaringClass().isInterface() && method.isDefault()) {
                return DefaultMethodInvoker.invoke(proxy, method, args);
            }
            throw new UnsupportedOperationException("combined transformer proxy: unexpected method " + method);
        }

        private boolean isTransformMethod(final Method method) {
            return method.getDeclaringClass() == ValueTransformer.class
                    && method.getName().startsWith("transform")
                    && (method.getParameterCount() == 1 || method.getParameterCount() == 3);
        }

        private Object chain(final Method method, final Object[] args) throws Exception {
            if (method.getParameterCount() == 1) {
                Object value = args[0];
                for (final ValueTransformer transformer : transformers) {
                    value = method.invoke(transformer, value);
                }
                return value;
            }
            for (final ValueTransformer transformer : transformers) {
                method.invoke(transformer, args);
            }
            return null;
        }

        private String combinedDescription() {
            final List<String> names = new ArrayList<>(transformers.size());
            for (final ValueTransformer transformer : transformers) {
                names.add(transformer.describe());
            }
            final String joined = String.join(", ", names);
            return desc == null ? joined : desc + ", " + joined;
        }
    }
}
