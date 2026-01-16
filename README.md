# PE-Insight
PE-Insight - средство для статического анализа PE-файлов на Windows(x86, x86_64).
### Реализованные директории:
1. Export Table
2. Import Table (с маппингом IAT/ILT для разрешения имен)
3. Resource Table (рекурсивно)
4. Exception Table (полный разбор x64 с UNWIND_INFO и LSDA. Размер LSDA получен либо через название PR из Import Table ,либо из предположения, что блоки UNWIND_INFO идут подряд)
5. Security Table (сертификаты)
6. Relocation Table (базовые поправки)
7. Debug Directory (PDB пути, GUID, Age)
8. TLS Directory (Callback-функции)
9. Load Config Directory (CFG, Cookies, SafeSEH)
10. Delay Import Descriptor
### Особенности реализации:
* Создает структуру папок для экспорта данных.
* Выборочно дампит компоненты PE-файла.
* Парсер оформлен как шаблонный класс в едином файле.
* Программа защищена от падений при обработке битых, модифицированных или упакованных файлов.
* Реализованы строгие проверки границ и валидация строк.