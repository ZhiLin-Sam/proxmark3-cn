/****************************************************************************
** Meta object code from reading C++ file 'proxguiqt.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.15.13)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "proxguiqt.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'proxguiqt.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.15.13. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_Plot_t {
    QByteArrayData data[14];
    char stringdata0[109];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_Plot_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_Plot_t qt_meta_stringdata_Plot = {
    {
QT_MOC_LITERAL(0, 0, 4), // "Plot"
QT_MOC_LITERAL(1, 5, 15), // "startMaxChanged"
QT_MOC_LITERAL(2, 21, 0), // ""
QT_MOC_LITERAL(3, 22, 8), // "uint32_t"
QT_MOC_LITERAL(4, 31, 8), // "startMax"
QT_MOC_LITERAL(5, 40, 17), // "graphStartChanged"
QT_MOC_LITERAL(6, 58, 10), // "graphStart"
QT_MOC_LITERAL(7, 69, 4), // "Zoom"
QT_MOC_LITERAL(8, 74, 6), // "factor"
QT_MOC_LITERAL(9, 81, 4), // "refX"
QT_MOC_LITERAL(10, 86, 6), // "MoveTo"
QT_MOC_LITERAL(11, 93, 3), // "pos"
QT_MOC_LITERAL(12, 97, 4), // "Move"
QT_MOC_LITERAL(13, 102, 6) // "offset"

    },
    "Plot\0startMaxChanged\0\0uint32_t\0startMax\0"
    "graphStartChanged\0graphStart\0Zoom\0"
    "factor\0refX\0MoveTo\0pos\0Move\0offset"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_Plot[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       6,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       2,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    1,   44,    2, 0x06 /* Public */,
       5,    1,   47,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       7,    2,   50,    2, 0x0a /* Public */,
      10,    1,   55,    2, 0x0a /* Public */,
      10,    1,   58,    2, 0x0a /* Public */,
      12,    1,   61,    2, 0x0a /* Public */,

 // signals: parameters
    QMetaType::Void, 0x80000000 | 3,    4,
    QMetaType::Void, 0x80000000 | 3,    6,

 // slots: parameters
    QMetaType::Void, QMetaType::Double, 0x80000000 | 3,    8,    9,
    QMetaType::Void, 0x80000000 | 3,   11,
    QMetaType::Void, QMetaType::Int,   11,
    QMetaType::Void, QMetaType::Int,   13,

       0        // eod
};

void Plot::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<Plot *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->startMaxChanged((*reinterpret_cast< uint32_t(*)>(_a[1]))); break;
        case 1: _t->graphStartChanged((*reinterpret_cast< uint32_t(*)>(_a[1]))); break;
        case 2: _t->Zoom((*reinterpret_cast< double(*)>(_a[1])),(*reinterpret_cast< uint32_t(*)>(_a[2]))); break;
        case 3: _t->MoveTo((*reinterpret_cast< uint32_t(*)>(_a[1]))); break;
        case 4: _t->MoveTo((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 5: _t->Move((*reinterpret_cast< int(*)>(_a[1]))); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (Plot::*)(uint32_t );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&Plot::startMaxChanged)) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (Plot::*)(uint32_t );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&Plot::graphStartChanged)) {
                *result = 1;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject Plot::staticMetaObject = { {
    QMetaObject::SuperData::link<QWidget::staticMetaObject>(),
    qt_meta_stringdata_Plot.data,
    qt_meta_data_Plot,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *Plot::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *Plot::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_Plot.stringdata0))
        return static_cast<void*>(this);
    return QWidget::qt_metacast(_clname);
}

int Plot::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QWidget::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 6)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 6;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 6)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 6;
    }
    return _id;
}

// SIGNAL 0
void Plot::startMaxChanged(uint32_t _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}

// SIGNAL 1
void Plot::graphStartChanged(uint32_t _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 1, _a);
}
struct qt_meta_stringdata_ProxWidget_t {
    QByteArrayData data[10];
    char stringdata0[127];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_ProxWidget_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_ProxWidget_t qt_meta_stringdata_ProxWidget = {
    {
QT_MOC_LITERAL(0, 0, 10), // "ProxWidget"
QT_MOC_LITERAL(1, 11, 14), // "applyOperation"
QT_MOC_LITERAL(2, 26, 0), // ""
QT_MOC_LITERAL(3, 27, 14), // "stickOperation"
QT_MOC_LITERAL(4, 42, 16), // "vchange_autocorr"
QT_MOC_LITERAL(5, 59, 1), // "v"
QT_MOC_LITERAL(6, 61, 15), // "vchange_askedge"
QT_MOC_LITERAL(7, 77, 15), // "vchange_dthr_up"
QT_MOC_LITERAL(8, 93, 17), // "vchange_dthr_down"
QT_MOC_LITERAL(9, 111, 15) // "updateNavSlider"

    },
    "ProxWidget\0applyOperation\0\0stickOperation\0"
    "vchange_autocorr\0v\0vchange_askedge\0"
    "vchange_dthr_up\0vchange_dthr_down\0"
    "updateNavSlider"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_ProxWidget[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       7,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags
       1,    0,   49,    2, 0x0a /* Public */,
       3,    0,   50,    2, 0x0a /* Public */,
       4,    1,   51,    2, 0x0a /* Public */,
       6,    1,   54,    2, 0x0a /* Public */,
       7,    1,   57,    2, 0x0a /* Public */,
       8,    1,   60,    2, 0x0a /* Public */,
       9,    0,   63,    2, 0x0a /* Public */,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Int,    5,
    QMetaType::Void, QMetaType::Int,    5,
    QMetaType::Void, QMetaType::Int,    5,
    QMetaType::Void, QMetaType::Int,    5,
    QMetaType::Void,

       0        // eod
};

void ProxWidget::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<ProxWidget *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->applyOperation(); break;
        case 1: _t->stickOperation(); break;
        case 2: _t->vchange_autocorr((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 3: _t->vchange_askedge((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 4: _t->vchange_dthr_up((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 5: _t->vchange_dthr_down((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 6: _t->updateNavSlider(); break;
        default: ;
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject ProxWidget::staticMetaObject = { {
    QMetaObject::SuperData::link<QWidget::staticMetaObject>(),
    qt_meta_stringdata_ProxWidget.data,
    qt_meta_data_ProxWidget,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *ProxWidget::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *ProxWidget::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_ProxWidget.stringdata0))
        return static_cast<void*>(this);
    return QWidget::qt_metacast(_clname);
}

int ProxWidget::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QWidget::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 7)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 7;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 7)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 7;
    }
    return _id;
}
struct qt_meta_stringdata_WorkerThread_t {
    QByteArrayData data[1];
    char stringdata0[13];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_WorkerThread_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_WorkerThread_t qt_meta_stringdata_WorkerThread = {
    {
QT_MOC_LITERAL(0, 0, 12) // "WorkerThread"

    },
    "WorkerThread"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_WorkerThread[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       0,    0, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

       0        // eod
};

void WorkerThread::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    (void)_o;
    (void)_id;
    (void)_c;
    (void)_a;
}

QT_INIT_METAOBJECT const QMetaObject WorkerThread::staticMetaObject = { {
    QMetaObject::SuperData::link<QThread::staticMetaObject>(),
    qt_meta_stringdata_WorkerThread.data,
    qt_meta_data_WorkerThread,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *WorkerThread::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *WorkerThread::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_WorkerThread.stringdata0))
        return static_cast<void*>(this);
    return QThread::qt_metacast(_clname);
}

int WorkerThread::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QThread::qt_metacall(_c, _id, _a);
    return _id;
}
struct qt_meta_stringdata_ProxGuiQT_t {
    QByteArrayData data[22];
    char stringdata0[376];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_ProxGuiQT_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_ProxGuiQT_t qt_meta_stringdata_ProxGuiQT = {
    {
QT_MOC_LITERAL(0, 0, 9), // "ProxGuiQT"
QT_MOC_LITERAL(1, 10, 21), // "ShowGraphWindowSignal"
QT_MOC_LITERAL(2, 32, 0), // ""
QT_MOC_LITERAL(3, 33, 24), // "RepaintGraphWindowSignal"
QT_MOC_LITERAL(4, 58, 21), // "HideGraphWindowSignal"
QT_MOC_LITERAL(5, 80, 10), // "ExitSignal"
QT_MOC_LITERAL(6, 91, 23), // "ShowPictureWindowSignal"
QT_MOC_LITERAL(7, 115, 3), // "img"
QT_MOC_LITERAL(8, 119, 29), // "ShowBase64PictureWindowSignal"
QT_MOC_LITERAL(9, 149, 5), // "char*"
QT_MOC_LITERAL(10, 155, 3), // "b64"
QT_MOC_LITERAL(11, 159, 23), // "HidePictureWindowSignal"
QT_MOC_LITERAL(12, 183, 26), // "RepaintPictureWindowSignal"
QT_MOC_LITERAL(13, 210, 16), // "_ShowGraphWindow"
QT_MOC_LITERAL(14, 227, 19), // "_RepaintGraphWindow"
QT_MOC_LITERAL(15, 247, 16), // "_HideGraphWindow"
QT_MOC_LITERAL(16, 264, 18), // "_ShowPictureWindow"
QT_MOC_LITERAL(17, 283, 24), // "_ShowBase64PictureWindow"
QT_MOC_LITERAL(18, 308, 18), // "_HidePictureWindow"
QT_MOC_LITERAL(19, 327, 21), // "_RepaintPictureWindow"
QT_MOC_LITERAL(20, 349, 5), // "_Exit"
QT_MOC_LITERAL(21, 355, 20) // "_StartProxmarkThread"

    },
    "ProxGuiQT\0ShowGraphWindowSignal\0\0"
    "RepaintGraphWindowSignal\0HideGraphWindowSignal\0"
    "ExitSignal\0ShowPictureWindowSignal\0"
    "img\0ShowBase64PictureWindowSignal\0"
    "char*\0b64\0HidePictureWindowSignal\0"
    "RepaintPictureWindowSignal\0_ShowGraphWindow\0"
    "_RepaintGraphWindow\0_HideGraphWindow\0"
    "_ShowPictureWindow\0_ShowBase64PictureWindow\0"
    "_HidePictureWindow\0_RepaintPictureWindow\0"
    "_Exit\0_StartProxmarkThread"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_ProxGuiQT[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
      17,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       8,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    0,   99,    2, 0x06 /* Public */,
       3,    0,  100,    2, 0x06 /* Public */,
       4,    0,  101,    2, 0x06 /* Public */,
       5,    0,  102,    2, 0x06 /* Public */,
       6,    1,  103,    2, 0x06 /* Public */,
       8,    1,  106,    2, 0x06 /* Public */,
      11,    0,  109,    2, 0x06 /* Public */,
      12,    0,  110,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
      13,    0,  111,    2, 0x08 /* Private */,
      14,    0,  112,    2, 0x08 /* Private */,
      15,    0,  113,    2, 0x08 /* Private */,
      16,    1,  114,    2, 0x08 /* Private */,
      17,    1,  117,    2, 0x08 /* Private */,
      18,    0,  120,    2, 0x08 /* Private */,
      19,    0,  121,    2, 0x08 /* Private */,
      20,    0,  122,    2, 0x08 /* Private */,
      21,    0,  123,    2, 0x08 /* Private */,

 // signals: parameters
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QImage,    7,
    QMetaType::Void, 0x80000000 | 9,   10,
    QMetaType::Void,
    QMetaType::Void,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QImage,    7,
    QMetaType::Void, 0x80000000 | 9,   10,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,

       0        // eod
};

void ProxGuiQT::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<ProxGuiQT *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->ShowGraphWindowSignal(); break;
        case 1: _t->RepaintGraphWindowSignal(); break;
        case 2: _t->HideGraphWindowSignal(); break;
        case 3: _t->ExitSignal(); break;
        case 4: _t->ShowPictureWindowSignal((*reinterpret_cast< const QImage(*)>(_a[1]))); break;
        case 5: _t->ShowBase64PictureWindowSignal((*reinterpret_cast< char*(*)>(_a[1]))); break;
        case 6: _t->HidePictureWindowSignal(); break;
        case 7: _t->RepaintPictureWindowSignal(); break;
        case 8: _t->_ShowGraphWindow(); break;
        case 9: _t->_RepaintGraphWindow(); break;
        case 10: _t->_HideGraphWindow(); break;
        case 11: _t->_ShowPictureWindow((*reinterpret_cast< const QImage(*)>(_a[1]))); break;
        case 12: _t->_ShowBase64PictureWindow((*reinterpret_cast< char*(*)>(_a[1]))); break;
        case 13: _t->_HidePictureWindow(); break;
        case 14: _t->_RepaintPictureWindow(); break;
        case 15: _t->_Exit(); break;
        case 16: _t->_StartProxmarkThread(); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (ProxGuiQT::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&ProxGuiQT::ShowGraphWindowSignal)) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (ProxGuiQT::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&ProxGuiQT::RepaintGraphWindowSignal)) {
                *result = 1;
                return;
            }
        }
        {
            using _t = void (ProxGuiQT::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&ProxGuiQT::HideGraphWindowSignal)) {
                *result = 2;
                return;
            }
        }
        {
            using _t = void (ProxGuiQT::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&ProxGuiQT::ExitSignal)) {
                *result = 3;
                return;
            }
        }
        {
            using _t = void (ProxGuiQT::*)(const QImage & );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&ProxGuiQT::ShowPictureWindowSignal)) {
                *result = 4;
                return;
            }
        }
        {
            using _t = void (ProxGuiQT::*)(char * );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&ProxGuiQT::ShowBase64PictureWindowSignal)) {
                *result = 5;
                return;
            }
        }
        {
            using _t = void (ProxGuiQT::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&ProxGuiQT::HidePictureWindowSignal)) {
                *result = 6;
                return;
            }
        }
        {
            using _t = void (ProxGuiQT::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&ProxGuiQT::RepaintPictureWindowSignal)) {
                *result = 7;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject ProxGuiQT::staticMetaObject = { {
    QMetaObject::SuperData::link<QObject::staticMetaObject>(),
    qt_meta_stringdata_ProxGuiQT.data,
    qt_meta_data_ProxGuiQT,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *ProxGuiQT::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *ProxGuiQT::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_ProxGuiQT.stringdata0))
        return static_cast<void*>(this);
    return QObject::qt_metacast(_clname);
}

int ProxGuiQT::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QObject::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 17)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 17;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 17)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 17;
    }
    return _id;
}

// SIGNAL 0
void ProxGuiQT::ShowGraphWindowSignal()
{
    QMetaObject::activate(this, &staticMetaObject, 0, nullptr);
}

// SIGNAL 1
void ProxGuiQT::RepaintGraphWindowSignal()
{
    QMetaObject::activate(this, &staticMetaObject, 1, nullptr);
}

// SIGNAL 2
void ProxGuiQT::HideGraphWindowSignal()
{
    QMetaObject::activate(this, &staticMetaObject, 2, nullptr);
}

// SIGNAL 3
void ProxGuiQT::ExitSignal()
{
    QMetaObject::activate(this, &staticMetaObject, 3, nullptr);
}

// SIGNAL 4
void ProxGuiQT::ShowPictureWindowSignal(const QImage & _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 4, _a);
}

// SIGNAL 5
void ProxGuiQT::ShowBase64PictureWindowSignal(char * _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 5, _a);
}

// SIGNAL 6
void ProxGuiQT::HidePictureWindowSignal()
{
    QMetaObject::activate(this, &staticMetaObject, 6, nullptr);
}

// SIGNAL 7
void ProxGuiQT::RepaintPictureWindowSignal()
{
    QMetaObject::activate(this, &staticMetaObject, 7, nullptr);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
