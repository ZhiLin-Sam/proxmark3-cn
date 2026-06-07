/********************************************************************************
** Form generated from reading UI file 'image.ui'
**
** Created by: Qt User Interface Compiler version 5.15.13
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef IMAGE_H
#define IMAGE_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QLabel>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_PictureForm
{
public:
    QVBoxLayout *verticalLayout_1;
    QLabel *lbl_pm;
    QLabel *lbl_sz;

    void setupUi(QWidget *Form)
    {
        if (Form->objectName().isEmpty())
            Form->setObjectName(QString::fromUtf8("Form"));
        Form->resize(400, 400);
        verticalLayout_1 = new QVBoxLayout(Form);
        verticalLayout_1->setObjectName(QString::fromUtf8("verticalLayout_1"));
        lbl_pm = new QLabel(Form);
        lbl_pm->setObjectName(QString::fromUtf8("lbl_pm"));

        verticalLayout_1->addWidget(lbl_pm);

        lbl_sz = new QLabel(Form);
        lbl_sz->setObjectName(QString::fromUtf8("lbl_sz"));

        verticalLayout_1->addWidget(lbl_sz);


        retranslateUi(Form);

        QMetaObject::connectSlotsByName(Form);
    } // setupUi

    void retranslateUi(QWidget *Form)
    {
        Form->setWindowTitle(QCoreApplication::translate("PictureForm", "Picture Viewer", nullptr));
        lbl_sz->setText(QCoreApplication::translate("PictureForm", "Image size", nullptr));
    } // retranslateUi

};

namespace Ui {
    class PictureForm: public Ui_PictureForm {};
} // namespace Ui

QT_END_NAMESPACE

#endif // IMAGE_H
