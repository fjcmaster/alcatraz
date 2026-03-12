## Sobre Nivdort 

Nivdort (Aka: BAYROB) es un troyano detectado por Microsoft por primera vez en 2013 [2] y reclasificado a mediados del 2015 [1] debido al surgimiento de diversas variantes (familia) y su proliferación. Este malware se distribuye mediante campañas de phishing via email distribuyendo un archivo malicioso en forma de ejecutable, archivo zip, falsos mensajes de WhatsApp y otras redes sociales. Este malware afecta al sistema operativo Windows. Una vez ejecutado por la victoria el malware gana persistencia en el sistema y tiene, entre otras capacidades, la de robar credenciales del usuario y enviarlas al C2 (control de comando del atacante).

Durante el año 2016 McAfee [3] alertó sobre una gran incremento en la distribución de este malware como spam mediante una campaña de mensajes de audio falsos de WhatsApp y como recibos de compra falsos. Ese mismo año el Gobierno de India [4] emite una letra sobre Nivdort. El 2018 la NHS de Inglaterra [5] volvió a alertar sobre una variante del malware, advirtiendo sobre sus capacidades para robar datos personales relacionadas a compras online, bancos y redes sociales.

[1] [https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Win32/Nivdort](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Win32/Nivdort)

[2] [https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=TrojanSpy:Win32/Nivdort](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=TrojanSpy:Win32/Nivdort)

[3] [https://www.mcafee.com/blogs/other-blogs/mcafee-labs/nivdort-data-stealing-trojan-arrives-via-spam/](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/nivdort-data-stealing-trojan-arrives-via-spam/)

[4] [https://www.csk.gov.in/alerts/nivdort.html](https://www.csk.gov.in/alerts/nivdort.html)

[5] [https://digital.nhs.uk/cyber-alerts/2018/cc-1932](https://digital.nhs.uk/cyber-alerts/2018/cc-1932)

## Reglas Yara

Las reglas Yara adjuntas en este repositorio son el resultado de un análisis inicial estático mediante el uso de herramientas como: file, binwalk2 y entroper. Este análisis no ha usado herramientas de desensamblando o decompilado, por tanto, las reglas Yara están enfocadas en IoC básicos y fácilmente identificables.

El análisis preliminar reveló la presencia de código compilado en .NET embebido en el .exe. También la presencia de recursos escondidos y cifrados. Las suposiciones iniciales hacen pensar que existe un proceso de carga dinámica en memoria de código .NET escondido en estos segmentos cifrados. Adicionalmente se ha identificado la capacidad de detección de análisis dinámicos y una serie de strings que apuntan a ejecución de código arbitrario, escalada de privilegios y manipulación de la memoria.

Strings sospechosos relacionados a lo anterior y utilizados en Yara:

-   `IsDebuggerPresen`: Para tratar de detectar análisis dinámicos y cambiar comportamiento.

-   `mscoree.dll`: DLL usada para ejecutar código C# o VB mediante el Framework de .NET.

-   `managed vector copy constructor iterator`: Mensaje relacionado a la manipulación de memoria y a la carga dinámica de código .NET.

-   `SystemRoot`: Cadena que podría estar asociada a elevación de privilegios.

-   `cmd.exe`: Usado para ejecución arbitraria de código.

-   `GAIsProcessorFeaturePresent`: API no oficial de Windows ni en estándares de NET.

-   `Copyright (c) 1992-2004 by P.J. Plauger, licensed by Dinkumware, Ltd. ALL RIGHTS RESERVED`: Copyright legitimo usado por el Malware.

