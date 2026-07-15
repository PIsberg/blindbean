package se.deversity.blindbean.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a field whose type is itself a {@link BlindEntity}, so the generated wrapper can reach into
 * it.
 *
 * <p>Encryption does not compose by itself. Given an {@code Order} holding a {@code Customer} whose
 * balance is {@code @Homomorphic}, {@code OrderBlindWrapper} knew nothing about the balance — you
 * had to reach through the object graph and wrap the inner entity by hand at every call site, which
 * is exactly the boilerplate the annotations exist to remove.
 *
 * <pre>{@code
 * @BlindEntity
 * public class Order {
 *     @BlindNested
 *     private Customer customer;      // Customer is itself a @BlindEntity
 *     ...
 * }
 *
 * var order = new OrderBlindWrapper(o);
 * order.customer().encryptBalance(new BigDecimal("19.99"));   // reaches straight through
 * }</pre>
 *
 * <p>The accessor returns the nested entity's own wrapper, so everything that entity supports —
 * encrypt, decrypt, the arithmetic, rotation — is available through it, and each nested entity keeps
 * its own scheme. A null nested entity yields a null wrapper rather than a
 * {@code NullPointerException} several frames deep.
 *
 * <p>Deliberately explicit: the processor does not go hunting for {@code @BlindEntity}-typed fields
 * on its own, because silently generating accessors into a neighbouring object graph is not a thing
 * a compile-time tool should do behind your back.
 *
 * <p>Nesting is not a way around the scheme rules. The nested entity is encrypted under whatever
 * schemes its own fields declare, and its context still has to be initialised — an {@code Order}
 * with a BFV-nested field still needs the native library.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface BlindNested {
}
