 1. Подготовка к курсу. Проект Gradle
git clone https://github.com/<ваш-логин>/otus-homeworks.git
cd otus-homeworks
git checkout -b hw01-gradle
gradle init --type java-library
dependencies {
    implementation("com.google.guava:guava:33.1.2-jre")
}
plugins {
    java
}
repositories {
    mavenCentral()
}
dependencies {
    implementation("com.google.guava:guava:33.1.2-jre")
}
include("hw01-gradle")
package ru.otus.hw;

import com.google.common.base.Joiner;


public class HelloOtus {
    public static void main(String[] args) {
        Joiner joiner = Joiner.on(" ").skipNulls();
        String result = joiner.join("Hello", "OTUS!");
        System.out.println(result);
    }
}
tasks.jar {
    manifest {
        attributes["Main-Class"] = "ru.otus.hw.HelloOtus"
    }
    from {
        configurations.runtimeClasspath.get().filter { it.name.endsWith("jar") }.map { zipTree(it) }
    }
}
./gradlew :hw01-gradle:jar
2. Контейнеры и алгоритмы. Применение коллекций
package homework;

import java.util.*;
import java.util.stream.Collectors;

public class CollectionsTask {

    /**
     * Метод для удаления дубликатов из списка строк
     */
    public List<String> removeDuplicates(List<String> input) {
        // Используем HashSet для автоматического удаления дубликатов
        return new ArrayList<>(new HashSet<>(input));
    }

    /**
     * Метод для подсчета количества каждого элемента в списке
     */
    public Map<String, Integer> countElements(List<String> input) {
        // Используем HashMap для хранения результатов
        Map<String, Integer> result = new HashMap<>();
        
        for (String item : input) {
            result.put(item, result.getOrDefault(item, 0) + 1);
        }
        
        return result;
    }

    /**
     * Метод для сортировки списка строк по длине
     */
    public List<String> sortByLength(List<String> input) {
        // Используем Stream API для сортировки
        return input.stream()
                .sorted(Comparator.comparingInt(String::length))
                .collect(Collectors.toList());
    }

    /**
     * Метод для поиска уникальных элементов в двух списках
     */
    public Set<String> findUnique(List<String> list1, List<String> list2) {
        // Используем Set для хранения уникальных элементов
        Set<String> set1 = new HashSet<>(list1);
        Set<String> set2 = new HashSet<>(list2);
        
        // Находим разницу между множествами
        set1.removeAll(set2);
        set2.removeAll(new HashSet<>(list1));
        
        // Объединяем результаты
        set1.addAll(set2);
        return set1;
    }
}
3. Аннотации. Свой тестовый фреймворк
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface Test {}

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface Before {}

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface After {}

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface Test {}

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface Before {}

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface After {}
public class SampleTest {
    @Before
    public void setUp() { System.out.println("Before"); }

    @Test
    public void test1() { System.out.println("Test 1"); }
    @Test
    public void test2() { System.out.println("Test 2"); }
    @After
    public void tearDown() { System.out.println("After"); }
}
public class TestRunner {
    public static void run(Class<?> testClass) {
        Method[] methods = testClass.getDeclaredMethods();
        List<Method> beforeMethods = Arrays.stream(methods)
            .filter(m -> m.isAnnotationPresent(Before.class))
            .collect(Collectors.toList());
        List<Method> testMethods = Arrays.stream(methods)
            .filter(m -> m.isAnnotationPresent(Test.class))
            .collect(Collectors.toList());
        List<Method> afterMethods = Arrays.stream(methods)
            .filter(m -> m.isAnnotationPresent(After.class))
            .collect(Collectors.toList());

        int total = testMethods.size(), passed = 0, failed = 0;

        for (Method test : testMethods) {
            Object instance = testClass.getDeclaredConstructor().newInstance();
            try {
                for (Method before : beforeMethods) before.invoke(instance);
                test.invoke(instance);
                passed++;
            } catch (Throwable e) {
                failed++;
                System.err.println("Fail: " + test.getName() + ", reason: " + e.getMessage());
            } finally {
                for (Method after : afterMethods) after.invoke(instance);
            }
        }

        System.out.printf("Total: %d, Passed: %d, Failed: %d%n", total, passed, failed);
    }
}
public static void main(String[] args) {
    TestRunner.run(SampleTest.class);
}
4. Сборщик мусора. Определение нужного размера хипа
tasks.withType<JavaExec> {
    jvmArgs = listOf("-Xmx256m", "-Xms256m")
}
./gradlew homework:run
Размер хипа	Время (мс)
256 МБ	18 284
2 ГБ	12 345

5. Байт‑код, class‑loader, инструментация, ASM. Автоматическое логирование
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface Log {}
public class TestLogging {
    @Log
    public void calculation(int param) {
        System.out.println("Calculation with param: " + param);
    }

    @Log
    public void calculation(int param1, int param2) {
        System.out.println("Sum: " + (param1 + param2));
    }

    @Log
    public void calculation(int param1, int param2, String param3) {
        System.out.println("Params: " + param1 + ", " + param2 + ", " + param3);
    }
}
import org.objectweb.asm.*;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;

public class LogAgent {
    public static void premain(String agentArgs, Instrumentation instrumentation) {
        instrumentation.addTransformer(new LogTransformer());
    }

    static class LogTransformer implements ClassFileTransformer {
        @Override
        public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                              ProtectionDomain protectionDomain, byte[] classFileBuffer) {
            if (className == null || className.startsWith("java/") || className.startsWith("javax/")) {
                return null;
            }

            ClassReader reader = new ClassReader(classFileBuffer);
            ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_FRAMES);
            reader.accept(new LogClassVisitor(writer), ClassReader.SKIP_DEBUG);
            return writer.toByteArray();
        }
    }

    static class LogClassVisitor extends ClassVisitor {
        LogClassVisitor(ClassWriter writer) {
            super(Opcodes.ASM9, writer);
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor,
                                      String signature, String[] exceptions) {
            MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
            return new LogMethodVisitor(mv, name, descriptor);
        }
    }

    static class LogMethodVisitor extends MethodVisitor {
        private final String methodName;
        private final Type[] argTypes;

        LogMethodVisitor(MethodVisitor mv, String methodName, String descriptor) {
            super(Opcodes.ASM9, mv);
            this.methodName = methodName;
            this.argTypes = Type.getArgumentTypes(descriptor);
        }

        @Override
        public AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {
            AnnotationVisitor av = super.visitAnnotation(descriptor, visible);
            if ("LLog;".equals(descriptor)) {
                // Вставляем код логирования при обнаружении аннотации @Log
                insertLoggingCode();
            }
            return av;
        }

        private void insertLoggingCode() {
            // Получаем System.out
            mv.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");

            // Создаем StringBuilder для сборки строки
            mv.visitTypeInsn(Opcodes.NEW, "java/lang/StringBuilder");
            mv.visitInsn(Opcodes.DUP);
            mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "()V", false);

            // Добавляем префикс
            mv.visitLdcInsn("executed method: " + methodName + ", params: ");
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
                    "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);

            // Перебираем аргументы и добавляем их в строку
            for (int i = 0; i < argTypes.length; i++) {
                if (i > 0) {
                    mv.visitLdcInsn(", ");
                    mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
                            "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
                }

                // Загружаем аргумент (i+1 из-за this в 0-й позиции)
                mv.visitVarInsn(argTypes[i].getOpcode(Opcodes.ILOAD), i + 1);

                // Преобразуем в строку (для примитивов используем valueOf)
                String valueOfMethod = argTypes[i].getClassName();
                if (argTypes[i].getSort() == Type.OBJECT) {
                    valueOfMethod = "toString";
                } else {
                    valueOfMethod = "valueOf";
                }
                mv.visitMethodInsn(Opcodes.INVOKESTATIC, argTypes[i].getClassName(),
                        valueOfMethod, "(" + argTypes[i].getDescriptor() + ")Ljava/lang/String;", false);

                mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
                        "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
            }

            // Выводим собранную строку
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "toString",
                    "()Ljava/lang/String;", false);
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println",
                    "(Ljava/lang/String;)V", false);
        }
    }
}
Manifest-Version: 1.0
Premain-Class: LogAgent
jar cvfm log-agent.jar MANIFEST.MF LogAgent.class LogAgent$*.class
java -javaagent:log-agent.jar -cp your-app.jar Demo
public class Demo {
    public static void main(String[] args) {
        TestLogging logging = new TestLogging();
        logging.calculation(6);
        logging.calculation(3, 4);
        logging.calculation(1, 2, "test");
    }
}
executed method: calculation, params: 6
Calculation with param: 6
executed method: calculation, params: 3, 4
Sum: 7
executed method: calculation, params: 1, 2, test
Params: 1, 2, test

6. Концепты проектирования ООП. Эмулятор АТМ
public enum Denomination {
    TEN(10),
    FIFTY(50),
    HUNDRED(100),
    FIVE_HUNDRED(500),
    THOUSAND(1000);

    private final int value;

    Denomination(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }
}
7. Structural patterns. Обработчик сообщений
public interface MessageHandler {
    void handle(String message);
}
public class SimpleHandler implements MessageHandler {
    public void handle(String message) {
        System.out.println("Handling: " + message);
    }
}
public class LoggingHandler implements MessageHandler {
    private final MessageHandler delegate;

    public LoggingHandler(MessageHandler delegate) {
        this.delegate = delegate;
    }

    public void handle(String message) {
        System.out.println("LOG: Received message: " + message);
        delegate.handle(message);
    }
}
MessageHandler handler = new LoggingHandler(new SimpleHandler());
handler.handle("Hello");
// Вывод:
// LOG: Received message: Hello
// Handling: Hello
8. Сериализация. Обработчик JSON‑ов
public class User {
    private String name;
    private int age;
    // геттеры/сеттеры
}
ObjectMapper mapper = new ObjectMapper();
User user = mapper.readValue(new File("input.json"), User.class);
user.setName(user.getName().toUpperCase()); //  обработка
mapper.writeValue(new File("output.json"), user);
implementation("com.fasterxml.jackson.core:jackson-databind:2.15.3")
{
  "name": "alice",
  "age": 30
}
{
  "name": "ALICE",
  "age": 30
}
9. JDBC. Самодельный ORM
public class EntityClassMetaData<T> {
    private final Class<T> clazz;
    private final String tableName;
    private final List<String> fieldNames;
    private final String idFieldName;

    public EntityClassMetaData(Class<T> clazz) {
        this.clazz = clazz;
        this.tableName = clazz.getSimpleName().toLowerCase();
        this.fieldNames = Arrays.stream(clazz.getDeclaredFields())
                .map(Field::getName)
                .collect(Collectors.toList());
        this.idFieldName = "id"; // предполагаем поле id
    }

    // геттеры
}
public class EntitySQLMetaData<T> {
    private final EntityClassMetaData<T> meta;

    public EntitySQLMetaData(EntityClassMetaData<T> meta) {
        this.meta = meta;
    }

    public String getSelectByIdQuery() {
        return String.format("SELECT * FROM %s WHERE %s = ?", 
                meta.getTableName(), meta.getIdFieldName());
    }

    public String getInsertQuery() {
        String columns = meta.getFieldNames().stream()
                .filter(f -> !f.equals(meta.getIdFieldName()))
                .collect(Collectors.joining(", "));
        String placeholders = meta.getFieldNames().stream()
                .filter(f -> !f.equals(meta.getIdFieldName()))
                .map(f -> "?")
                .collect(Collectors.joining(", "));
        return String.format("INSERT INTO %s (%s) VALUES (%s)",
                meta.getTableName(), columns, placeholders);
    }

    // другие запросы (update, delete)
}
public class DataTemplateJdbc<T> {
    private final JdbcTemplate jdbc;
    private final EntitySQLMetaData<T> sqlMeta;
    private final EntityClassMetaData<T> classMeta;

    public DataTemplateJdbc(DataSource dataSource, EntityClassMetaData<T> meta) {
        this.jdbc = new JdbcTemplate(dataSource);
        this.sqlMeta = new EntitySQLMetaData<>(meta);
        this.classMeta = meta;
    }

    public Optional<T> findById(long id) {
        return jdbc.query(sqlMeta.getSelectByIdQuery(),
                new Object[]{id},
                rs -> {
                    if (!rs.next()) return Optional.empty();
                    T obj = classMeta.getClazz().getDeclaredConstructor().newInstance();
                    // заполнение полей из ResultSet
                    return Optional.of(obj);
                });
    }

    public long insert(T obj) {
        KeyHolder keyHolder = new GeneratedKeyHolder();
        jdbc.update((PreparedStatementCreator) con -> {
            PreparedStatement ps = con.prepareStatement(
                    sqlMeta.getInsertQuery(), new String[]{"id"});
            // установка параметров
            return ps;
        }, keyHolder);
        return keyHolder.getKey().longValue();
    }
}
public class HomeWork {
    public static void main(String[] args) throws Exception {
        DataSource dataSource = createDataSource(); // настройка DataSource
        EntityClassMetaData<Client> meta = new EntityClassMetaData<>(Client.class);
        DataTemplateJdbc<Client> template = new DataTemplateJdbc<>(dataSource, meta);

        Client client = new Client("John");
        long id = template.insert(client);
        Optional<Client> loaded = template.findById(id);
        System.out.println(loaded.orElseThrow());
    }

    private static DataSource createDataSource() {
        // настройка подключения к Docker-контейнеру с БД
    }
}
10. JPQL. Использование Hibernate
@Entity
@Table(name = "client")
public class Client {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne(cascade = CascadeType.ALL, orphanRemoval = true)
    @JoinColumn(name = "address_id")
    private Address address;

    @OneToMany(cascade = CascadeType.ALL, orphanRemoval = true, mappedBy = "client")
    private List<Phone> phones = new ArrayList<>();

    // геттеры/сеттеры
}

@Entity
@Table(name = "address")
public class Address {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String street;

    // геттеры/сеттеры
}

@Entity
@Table(name = "phone")
public class Phone {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String number;

    @ManyToOne
    @JoinColumn(name = "client_id")
    private Client client;

    // геттеры/сеттеры
}
11. Типы ссылок. Кэширование

public class MyCache<K, V> {
    private final WeakHashMap<K, SoftReference<V>> cache = new WeakHashMap<>();


    public void put(K key, V value) {
        cache.put(key, new SoftReference<>(value));
    }

    public V get(K key) {
        SoftReference<V> ref = cache.get(key);
        return ref != null ? ref.get() : null;
    }

    public boolean containsKey(K key) {
        return cache.containsKey(key) && cache.get(key).get() != null;
    }
}
public class DBService {
    private final MyCache<Long, Client> cache = new MyCache<>();
    private final DataTemplateJdbc<Client> jdbcTemplate;

    public Client findById(Long id) {
        if (cache.containsKey(id)) {
            return cache.get(id);
        }
        Client client = jdbcTemplate.findById(id).orElse(null);
        if (client != null) {
            cache.put(id, client);
        }
        return client;
    }
}
12. Веб‑сервер
implementation("org.springframework.boot:spring-boot-starter-web")
implementation("org.springframework.boot:spring-boot-starter-data-jpa")
@RestController
@RequestMapping("/admin")
public class AdminController {
    @GetMapping("/clients")
    public List<Client> getAllClients() {
        return dbService.getAllClients();
    }

    @PostMapping("/clients")
    public ResponseEntity<Client> createClient(@RequestBody Client client) {
        Client saved = dbService.saveClient(client);
        return ResponseEntity.created(URI.create("/admin/clients/" + saved.getId())).body(saved);
    }
}
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .formLogin();
        return http.build();
    }
}
13. Dependency injection. Собственный IoC контейнер
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class AppComponentsContainerImpl implements AppComponentsContainer {

    private final Map<String, Object> components = new HashMap<>();

    public AppComponentsContainerImpl(Class<?> initialConfigClass) {
        processConfigurationClass(initialConfigClass);
    }

    private void processConfigurationClass(Class<?> configClass) {
        // Ищем методы с аннотацией @Bean
        for (var method : configClass.getDeclaredMethods()) {
            if (method.isAnnotationPresent(Bean.class)) {
                try {
                    Object component = method.invoke(configClass.getDeclaredConstructor().newInstance());
                    String beanName = extractBeanName(method);
                    components.put(beanName, component);
                } catch (Exception e) {
                    throw new RuntimeException("Error creating bean: " + method.getName(), e);
                }
            }
        }

        // Ищем поля с аннотацией @Component
        for (Field field : configClass.getDeclaredFields()) {
            if (field.isAnnotationPresent(Component.class)) {
                try {
                    field.setAccessible(true);
                    Object component = field.getType().getDeclaredConstructor().newInstance();
                    String beanName = field.getName();
                    components.put(beanName, component);
                } catch (Exception e) {
                    throw new RuntimeException("Error creating component: " + field.getName(), e);
                }
            }
        }
    }

    private String extractBeanName(java.lang.reflect.Method method) {
        Bean annotation = method.getAnnotation(Bean.class);
        if (!annotation.name().isEmpty()) {
            return annotation.name();
        }
        return method.getName();
    }

    @Override
    public <T> T getAppComponent(Class<T> componentClass) {
        return (T) components.values().stream()
                .filter(componentClass::isInstance)
                .findFirst()
                .orElseThrow(() -> new RuntimeException("Component not found: " + componentClass.getName()));
    }

    @Override
    public <T> T getAppComponent(String name) {
        Object component = components.get(name);
        if (component == null) {
            throw new RuntimeException("Component not found: " + name);
        }
        return (T) component;
    }
}
14. Spring Data JDBC. Веб‑приложение на Spring Boot
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-jdbc</artifactId>
    </dependency>
    <dependency>
        <groupId>org.thymeleaf</groupId>
        <artifactId>thymeleaf-spring6</artifactId>
    </dependency>
    <dependency>
        <groupId>com.h2database</groupId>
        <artifactId>h2</artifactId>
        <scope>runtime</scope>
    </dependency>
</dependencies>
@Table("client")
public class Client {
    @Id
    private Long id;
    private String name;
    // геттеры/сеттеры
}
public interface ClientRepository extends CrudRepository<Client, Long> {
}
@Controller
public class ClientController {

    private final ClientRepository clientRepository;

    public ClientController(ClientRepository clientRepository) {
        this.clientRepository = clientRepository;
    }

    @GetMapping("/clients")
    public String listClients(Model model) {
        model.addAttribute("clients", clientRepository.findAll());
        return "clients";
    }

    @PostMapping("/clients")
    public String createClient(@ModelAttribute Client client) {
        clientRepository.save(client);
        return "redirect:/clients";
    }
}
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head><title>Clients</title></head>
<body>
    <h1>Clients</h1>
    <table>
        <tr><th>ID</th><th>Name</th></tr>
        <tr th:each="client : ${clients}">
            <td th:text="${client.id}"></td>
            <td th:text="${client.name}"></td>
        </tr>
    </table>
    <form action="/clients" method="post">
        <input type="text" name="name" placeholder="Name"/>
        <button type="submit">Add</button>
    </form>
</body>
</html>
15. Executors. Последовательность чисел
public class NumberSequence {

    private static final Object lock = new Object();
    private static boolean turn = true; // true = поток 1, false = поток 2

    public static void main(String[] args) {
        Thread thread1 = new Thread(() -> printSequence(1));
        Thread thread2 = new Thread(() -> printSequence(2));

        thread1.start();
        thread2.start();
    }

    private static void printSequence(int threadId) {
        for (int cycle = 0; cycle < 3; cycle++) { // 3 цикла для наглядности
            synchronized (lock) {
                if (threadId == 1 && turn || threadId == 2 && !turn) {
                    // Прямой счёт
                    for (int i = 1; i <= 10; i++) {
                        System.out.printf("Поток %d: %d%n", threadId, i);
                    }
                    // Обратный счёт
                    for (int i = 9; i >= 1; i--) {
                        System.out.printf("Поток %d: %d%n", threadId, i);
                    }
                    turn = !turn; // Передаём ход
                }
            }
            // Короткий sleep для чередования
            try { Thread.sleep(100); } catch (InterruptedException e) {}
        }
    }
}
16. Потокобезопасные коллекции. Queues

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class SensorDataProcessorBuffered {

    private final BlockingQueue<SensorData> buffer;
    private final SensorDataBufferedWriter writer;
    private final int bufferSize;

    public SensorDataProcessorBuffered(SensorDataBufferedWriter writer, int bufferSize) {
        this.writer = writer;
        this.bufferSize = bufferSize;
        this.buffer = new LinkedBlockingQueue<>(bufferSize);
    }

    public void onData(SensorData data) {
        buffer.add(data);
        if (buffer.size() >= bufferSize) {
            flush();
        }
    }

    public void flush() {
        var dataToWrite = new ArrayList<SensorData>();
        buffer.drainTo(dataToWrite);
        writer.write(dataToWrite);
    }
}
17. gRPC‑приложение «Убить босса»
syntax = "proto3";

package numbers;

service NumberGenerator {
  rpc getNumbers (NumbersRequest) returns (stream NumbersResponse);
}

message NumbersRequest {
  int32 firstValue = 1;
  int32 lastValue = 2;
}

message NumbersResponse {
  int32 value = 1;
}
import io.grpc.Server;
import io.grpc.ServerBuilder;
import io.grpc.stub.StreamObserver;
import java.io.IOException;
import java.util.concurrent.TimeUnit;

public class NumbersServer {

    private Server server;

    public void start() throws IOException {
        server = ServerBuilder.forPort(9090)
                .addService(new NumberGeneratorImpl())
                .build()
                .start();
        System.out.println("Server started, port: 9090");
    }

    public void stop() throws InterruptedException {
        if (server != null) {
            server.shutdown().awaitTermination(30, TimeUnit.SECONDS);
        }
    }

    private static class NumberGeneratorImpl extends NumberGeneratorGrpc.NumberGeneratorImplBase {

        @Override
        public void getNumbers(NumbersRequest request, StreamObserver<NumbersResponse> responseObserver) {
            int current = request.getFirstValue();
            int last = request.getLastValue();

            try {
                while (current <= last) {
                    NumbersResponse response = NumbersResponse.newBuilder()
                            .setValue(current)
                            .build();

                    responseObserver.onNext(response);

                    // Пауза 2 секунды
                    Thread.sleep(2000);
                    current++;
                }
                responseObserver.onCompleted();
            } catch (InterruptedException e) {
                responseObserver.onError(e);
            }
        }
    }

    public static void main(String[] args) throws Exception {
        NumbersServer server = new NumbersServer();
        server.start();
        server.blockUntilShutdown();
    }

    private void blockUntilShutdown() throws InterruptedException {
        if (server != null) {
            server.awaitTermination();
        }
    }
}
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.stub.StreamObserver;
import java.time.LocalDateTime;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

public class NumbersClient {

    private final ManagedChannel channel;
    private final NumberGeneratorGrpc.NumberGeneratorStub asyncStub;
    private AtomicInteger lastServerValue = new AtomicInteger(0);
    private volatile boolean serverDataUsed = true;

    public NumbersClient(String host, int port) {
        channel = ManagedChannelBuilder.forAddress(host, port)
                .usePlaintext()
                .build();
        asyncStub = NumberGeneratorGrpc.newStub(channel);
    }

    public void shutdown() throws InterruptedException {
        channel.shutdown().awaitTermination(5, TimeUnit.SECONDS);
    }

    public void requestNumbers(int first, int last) {
        NumbersRequest request = NumbersRequest.newBuilder()
                .setFirstValue(first)
                .setLastValue(last)
                .build();

        CountDownLatch finishLatch = new CountDownLatch(1);

        StreamObserver<NumbersResponse> responseObserver = new StreamObserver<>() {
            @Override
            public void onNext(NumbersResponse response) {
                int newValue = response.getValue();
                lastServerValue.set(newValue);
                serverDataUsed = false;
                System.out.printf("%s [grpc-default-executor-0] INFO r.o.n.client.ClientStreamObserver - new value:%d%n",
                        LocalDateTime.now(), newValue);
            }

            @Override
            public void onError(Throwable t) {
                finishLatch.countDown();
            }

            @Override
            public void onCompleted() {
                System.out.printf("%s [grpc-default-executor-0] INFO r.o.n.client.ClientStreamObserver - request completed%n",
                        LocalDateTime.now());
                finishLatch.countDown();
            }
        };

        asyncStub.getNumbers(request, responseObserver);

        startValueCalculation(finishLatch);
    }

    private void startValueCalculation(CountDownLatch finishLatch) {
        int currentValue = 0;

        for (int i = 0; i < 50; i++) {
            try {
                Thread.sleep(1000); // раз в секунду

                if (!serverDataUsed) {
                    currentValue = currentValue + lastServerValue.get() + 1;
                    serverDataUsed = true; // отметили, что использовали
                } else {
                    currentValue++;
                }

                System.out.printf("%s [main] INFO ru.otus.numbers.client.NumbersClient - currentValue:%d%n",
                        LocalDateTime.now(), currentValue);
            } catch (InterruptedException e) {
                break;
            }
        }

        try {
            finishLatch.await();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws Exception {
        NumbersClient client = new NumbersClient("localhost", 9090);
        System.out.printf("%s [main] INFO ru.otus.numbers.client.NumbersClient - numbers Client is starting...%n",
                LocalDateTime.now());

        client.requestNumbers(0, 30);

        client.shutdown();
    }
}
<dependencies>
    <dependency>
        <groupId>io.grpc</groupId>
        <artifactId>grpc-netty-shaded</artifactId>
        <version>1.66.0</version>
    </dependency>
    <dependency>
        <groupId>io.grpc</groupId>
        <artifactId>grpc-protobuf</artifactId>
        <version>1.66.0</version>
    </dependency>
    <dependency>
        <groupId>io.grpc</groupId>
        <artifactId>grpc-stub</artifactId>
        <version>1.66.0</version>
    </dependency>
</dependencies>
18. Реактивное приложение: комната 1408 в чате (Spring WebFlux)
import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Data;
import org.springframework.data.annotation.Id;

import java.time.LocalDateTime;

@Data
public class ChatMessage {
    @Id
    private String id;
    private String roomId;
    private String sender;
    private String content;
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime timestamp;
}
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import reactor.core.publisher.Flux;

public interface MessageRepository extends ReactiveMongoRepository<ChatMessage, String> {
    Flux<ChatMessage> findByRoomId(String roomId);
}
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Sinks;

import java.time.LocalDateTime;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

@Service
public class ChatService {
    private final MessageRepository messageRepository;
    private final Sinks.Many<ChatMessage> messageSink = Sinks.many().multicast().onBackpressureBuffer();
    private final Flux<ChatMessage> broadcast = messageSink.asFlux();

    // Храним все сообщения по комнатам (для загрузки истории)
    private final Map<String, Flux<ChatMessage>> roomHistory = new ConcurrentHashMap<>();

    public ChatService(MessageRepository messageRepository) {
        this.messageRepository = messageRepository;
    }

    // Отправка сообщения в комнату (кроме 1408)
    public Flux<ChatMessage> sendMessage(ChatMessage message) {
        if ("1408".equals(message.getRoomId())) {
            return Flux.error(new IllegalArgumentException("Cannot send messages to room 1408"));
        }

        message.setTimestamp(LocalDateTime.now());
        return messageRepository.save(message)
                .doOnNext(savedMsg -> messageSink.tryEmitNext(savedMsg))
                .thenMany(broadcast);
    }

    // Получение сообщений для комнаты
    public Flux<ChatMessage> getMessagesForRoom(String roomId) {
        if ("1408".equals(roomId)) {
            // Для комнаты 1408 — объединяем все сообщения из всех комнат
            return messageRepository.findAll()
                    .sort((a, b) -> a.getTimestamp().compareTo(b.getTimestamp()));
        } else {
            // Для обычных комнат — только их сообщения
            return messageRepository.findByRoomId(roomId);
        }
    }
}
import org.springframework.web.bind.annotation.*;
import org.springframework.http.MediaType;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/chat")
public class ChatController {
    private final ChatService chatService;

    public ChatController(ChatService chatService) {
        this.chatService = chatService;
    }

    @PostMapping("/send")
    public Mono<ChatMessage> sendMessage(@RequestBody ChatMessage message) {
        return chatService.sendMessage(message);
    }

    @GetMapping(value = "/room/{roomId}", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public Flux<ChatMessage> getMessages(@PathVariable String roomId) {
        return chatService.getMessagesForRoom(roomId);
    }
}
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.config.CorsRegistry;
import org.springframework.web.reactive.config.WebFluxConfigurer;

@Configuration
public class WebFluxConfig implements WebFluxConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOrigins("*")
                .allowedMethods("GET", "POST");
    }
}
<!DOCTYPE html>
<html>
<head>
    <title>Chat Room 1408</title>
</head>
<body>
    <h1>Комната 1408 (все сообщения)</h1>
    <div id="messages"></div>

    <script>
        const messagesDiv = document.getElementById('messages');

        const eventSource = new EventSource('/api/chat/room/1408');

        eventSource.onmessage = function(event) {
            const data = JSON.parse(event.data);
            const msg = document.createElement('div');
            msg.textContent = `[${data.timestamp}] ${data.sender}: ${data.content}`;
            messagesDiv.appendChild(msg);
        };
    </script>
</body>
</html>




